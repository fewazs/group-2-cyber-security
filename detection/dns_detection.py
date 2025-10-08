"""
DNS Tunneling Detection Logic
Loads captured DNS features and applies pattern-based rules to detect tunneling.
"""
import json
import re
import os
import time
import math

INPUT_FILE = os.path.join(os.path.dirname(__file__), '../capture/dns_traffic.json')
ALERT_LOG = os.path.join(os.path.dirname(__file__), '../prevention/alerts.log')
BLOCKLIST_FILE = os.path.join(os.path.dirname(__file__), '../prevention/blocklist.txt')
DEVICES_FILE = os.path.join(os.path.dirname(__file__), '../prevention/devices.json')

# Detection thresholds
MAX_QUERY_LEN = 100
MAX_FREQ_PER_SEC = 10
UNCOMMON_DOMAIN_REGEX = r"(spotify|facebook|tiktok)"  # whitelist

SPOTIFY_REAL_DOMAINS = [
    'spotify.com', 'api.spotify.com', 'spclient.wg.spotify.com', 'apresolve.spotify.com'
]

# Known tunneling domains
KNOWN_TUNNEL_DOMAINS = [
    'iodine.com', 'dnscat2.com', 'dns2tcp.com', 'tunnel.com'
]


# Helper: Entropy calculation
def calc_entropy(s):
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob])


def load_features():
    with open(INPUT_FILE) as f:
        return json.load(f)


def is_real_spotify(query):
    return any(domain in query for domain in SPOTIFY_REAL_DOMAINS)


def detect_spotify_tunneling(features):
    alerts = []
    real_spotify = 0
    fake_spotify = 0
    for feat in features:
        query = feat.get('query', '')
        qtype = feat.get('qtype', 'A')
        client_ip = feat.get('client_ip', '')
        # 1. Real vs Fake Spotify
        if 'spotify' in query:
            if is_real_spotify(query):
                real_spotify += 1
            else:
                fake_spotify += 1
                alerts.append((feat, 'Fake Spotify DNS tunneling detected'))
        # 2. Entropy analysis
        subdomain = query.split('.')[0] if '.' in query else query
        if len(subdomain) > 10 and calc_entropy(subdomain) > 4.0:
            alerts.append((feat, 'High entropy in subdomain'))
        # 3. Query length
        if len(query) > 80:
            alerts.append((feat, 'Unusually long DNS query'))
        # 4. Frequency analysis
        # (handled in main loop, see below)
        # 5. Unusual subdomain patterns
        if re.match(r'^[A-Za-z0-9+/=]{16,}$', subdomain):
            alerts.append((feat, 'Base64/hex encoded subdomain'))
        # 6. Known tunneling domains
        if any(tunnel in query for tunnel in KNOWN_TUNNEL_DOMAINS):
            alerts.append((feat, 'Known tunneling domain'))
        # 7. Non-standard query types
        if qtype in ['TXT', 'NULL', 'CNAME']:
            alerts.append((feat, f'Unusual DNS query type: {qtype}'))
        # 8. Geographic mismatch (placeholder, needs geoip)
        # if client_ip and not is_expected_region(client_ip):
        #     alerts.append((feat, 'Geographic mismatch for Spotify DNS'))
        # 9. Client behavior (placeholder, needs aggregation)
        # ...
    # 4. Frequency analysis (per second)
    freq_counter = {}
    for feat in features:
        ts = int(feat.get('timestamp', 0))
        freq_counter.setdefault(ts, 0)
        freq_counter[ts] += 1
    for ts, freq in freq_counter.items():
        if freq > 10:
            alerts.append(({'timestamp': ts}, f'High DNS query frequency: {freq}/sec'))
    return alerts, real_spotify, fake_spotify


def log_alerts(alerts):
    with open(ALERT_LOG, "w") as f:
        for feat, reason in alerts:
            f.write(f"ALERT: {reason} | {feat}\n")
    print(f"Logged {len(alerts)} alerts to {ALERT_LOG}")


def log_blocklist(alerts):
    blocked = set()
    for feat, reason in alerts:
        query = feat.get('query', '')
        if 'Fake Spotify DNS tunneling detected' in reason or 'Known tunneling domain' in reason:
            blocked.add(query)
    with open(BLOCKLIST_FILE, 'w') as f:
        for domain in blocked:
            f.write(domain + '\n')
    print(f"Blocked {len(blocked)} domains written to {BLOCKLIST_FILE}")


def log_devices(features):
    devices = set()
    for feat in features:
        if 'src_ip' in feat:
            devices.add(feat['src_ip'])
    with open(DEVICES_FILE, 'w') as f:
        json.dump(list(devices), f)
    print(f"Logged {len(devices)} devices to {DEVICES_FILE}")


def continuous_detection():
    while True:
        features = load_features()
        alerts, real_spotify, fake_spotify = detect_spotify_tunneling(features)
        log_alerts(alerts)
        log_blocklist(alerts)
        log_devices(features)
        # Save stats for dashboard
        with open(os.path.join(os.path.dirname(__file__), '../prevention/spotify_stats.json'), 'w') as f:
            json.dump({
                'real_spotify': real_spotify,
                'fake_spotify': fake_spotify,
                'alerts': len(alerts)
            }, f)
        time.sleep(5)  # Check every 5 seconds


if __name__ == "__main__":
    continuous_detection()
