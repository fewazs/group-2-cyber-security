#!/usr/bin/env python3
"""
dns_tunnel_detector.py

Simple DNS tunneling detector using heuristics:
- High entropy in domain/subdomain (indicates encoded payloads)
- Very long domain or very long single label
- Many subdomain labels (deep subdomain depth)
- Base32/Base64-like label patterns
- High frequency of unique-looking subdomains for same base domain
- Suspicious TLDs / uncommon TLDs (basic list)
- NXDOMAIN spikes (if using DNS response parsing)

Usage:
    sudo python3 dns_tunnel_detector.py             # live sniffing on default iface
    python3 dns_tunnel_detector.py --pcap file.pcap  # analyze pcap file
    
"""

import argparse
import math
import re
import time
import csv
from collections import defaultdict, deque
from scapy.all import sniff, rdpcap, DNS, DNSQR, UDP, IP

# ---------- Configurable thresholds (tune for your environment) ----------
ENTROPY_THRESHOLD = 3.8          # entropy above this is suspicious
LONG_LABEL_LEN = 30              # a single label longer than this is suspicious
DOMAIN_LEN_THRESHOLD = 60        # full domain longer than this is suspicious
SUBDOMAIN_DEPTH = 4              # number of labels (excluding TLD) considered deep
BASE64_MATCH_LEN = 16            # label length above which we check base64/base32
SCORE_ALERT_THRESHOLD = 0.7      # score [0..1] above which we alert
SLIDING_WINDOW_SECONDS = 60      # window to count queries per second-ish metrics
UNIQUE_SUBDOMAIN_RATE = 0.6      # fraction of unique subdomains over window that is suspicious
MIN_QUERIES_FOR_RATE = 10        # minimum queries in window to evaluate unique subdomain rate

# A small set of common TLDs; everything else considered less common (for heuristic)
COMMON_TLDS = {
    "com", "net", "org", "edu", "gov", "io", "co", "us", "uk", "de", "jp", "cn",
    "ru", "fr", "au", "nl", "br", "it", "es", "ca"
}

# Base64/base32 regex-ish check (loose)
BASE64_RE = re.compile(r'^[A-Za-z0-9+/=]{%d,}$' % BASE64_MATCH_LEN)
BASE32_RE = re.compile(r'^[A-Z2-7]{%d,}$' % BASE64_MATCH_LEN)  # base32 is uppercase letters+2-7

# allowed characters for domain: letters, digits, hyphen
LABEL_ALLOWED_RE = re.compile(r'^[A-Za-z0-9-]+$')

# ---------- Utility functions ----------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    e = 0.0
    l = len(s)
    for count in freq.values():
        p = count / l
        e -= p * math.log2(p)
    return e

def is_base64_like(label: str) -> bool:
    # strip '=' padding for detection
    lab = label.rstrip('=')
    if len(lab) < BASE64_MATCH_LEN:
        return False
    if BASE64_RE.match(label):
        return True
    if BASE32_RE.match(label.upper()):
        return True
    return False

def label_character_profile(label: str):
    # returns dict of vowel ratio, digit ratio, unique char ratio, hyphen ratio
    if not label:
        return {}
    vowels = sum(1 for ch in label.lower() if ch in 'aeiou')
    digits = sum(1 for ch in label if ch.isdigit())
    hyphens = label.count('-')
    unique = len(set(label))
    l = len(label)
    return {
        'vowel_ratio': vowels / l,
        'digit_ratio': digits / l,
        'hyphen_ratio': hyphens / l,
        'unique_char_ratio': unique / l
    }

def extract_domain_parts(qname: str):
    # qname can be bytes or string; ensure string and strip trailing dot
    if isinstance(qname, bytes):
        qname = qname.decode('utf-8', errors='ignore')
    qname = qname.rstrip('.')
    labels = qname.split('.')
    if len(labels) == 0:
        return {'labels': [], 'tld': ''}
    tld = labels[-1].lower()
    return {'labels': labels, 'tld': tld}

# ---------- Detection engine ----------
class DNSTunnelDetector:
    def __init__(self):
        # sliding window store: domain->deque of timestamps of queries
        self.domain_times = defaultdict(deque)
        # for base domain grouping, we consider last 2 labels as base domain when possible
        self.base_domain_times = defaultdict(deque)
        # store recent queries for unique-subdomain-rate detection
        self.recent_queries = deque()  # (timestamp, base_domain, full_domain)
        self.alerted = set()

    def base_domain(self, labels):
        # naive base domain extraction: last two labels if possible (e.g., example.com)
        if len(labels) >= 2:
            return '.'.join(labels[-2:])
        elif labels:
            return labels[-1]
        return ''

    def score_domain(self, qname: str):
        parts = extract_domain_parts(qname)
        labels = parts['labels']
        tld = parts['tld']
        if not labels:
            return 0.0, {}

        full_domain = '.'.join(labels)
        scores = {}
        # features
        longest_label = max((len(l) for l in labels), default=0)
        domain_len = len(full_domain)
        label_count = len(labels)
        avg_label_len = domain_len / label_count if label_count else 0
        entropy_full = shannon_entropy(full_domain)
        entropy_label_max = max((shannon_entropy(l) for l in labels), default=0)
        base64_like_any = any(is_base64_like(l) for l in labels)
        long_label_present = longest_label >= LONG_LABEL_LEN
        deep_subdomain = (label_count - 1) >= SUBDOMAIN_DEPTH  # exclude TLD
        uncommon_tld = tld not in COMMON_TLDS

        # character profile of the most suspicious label
        suspect_label = max(labels, key=lambda x: len(x))
        profile = label_character_profile(suspect_label)

        # Build a heuristic score [0..1]
        score = 0.0
        weight_sum = 0.0

        # entropy contributions
        w = 1.4
        weight_sum += w
        score += w * (entropy_label_max / 6.0)  # entropy over single label scaled (6 is max-ish)

        # full-domain entropy
        w = 0.6
        weight_sum += w
        score += w * (entropy_full / 6.0)

        # base64/base32 heuristic
        w = 1.0
        weight_sum += w
        score += w * (1.0 if base64_like_any else 0.0)

        # long single label
        w = 0.9
        weight_sum += w
        score += w * (1.0 if long_label_present else 0.0)

        # very long domain
        w = 0.6
        weight_sum += w
        score += w * (min(domain_len / (DOMAIN_LEN_THRESHOLD * 2), 1.0))  # scaled

        # deep subdomain
        w = 0.6
        weight_sum += w
        score += w * (1.0 if deep_subdomain else 0.0)

        # uncommon tld
        w = 0.3
        weight_sum += w
        score += w * (1.0 if uncommon_tld else 0.0)

        # lots of digits (common in generated/subdomain)
        w = 0.4
        weight_sum += w
        score += w * (profile.get('digit_ratio', 0) * 1.0)

        # low vowel ratio (encoded string tends to have low vowel proportion)
        w = 0.4
        weight_sum += w
        score += w * (1.0 - profile.get('vowel_ratio', 0))

        # unique char ratio (very high unique ratio suspicious)
        w = 0.4
        weight_sum += w
        score += w * profile.get('unique_char_ratio', 0)

        # normalize
        final_score = (score / weight_sum) if weight_sum else 0.0
        # clamp
        final_score = max(0.0, min(1.0, final_score))

        features = {
            'domain_len': domain_len,
            'label_count': label_count,
            'longest_label': longest_label,
            'entropy_full': entropy_full,
            'entropy_label_max': entropy_label_max,
            'base64_like_any': base64_like_any,
            'deep_subdomain': deep_subdomain,
            'uncommon_tld': uncommon_tld,
            'profile': profile,
            'final_score': final_score
        }
        return final_score, features

    def update_counters_and_check_rate(self, qname: str, timestamp: float):
        parts = extract_domain_parts(qname)
        labels = parts['labels']
        if not labels:
            return None
        base_dom = self.base_domain(labels)
        # push timestamps into base domain deque
        dq = self.base_domain_times[base_dom]
        dq.append(timestamp)
        # remove old entries
        cutoff = timestamp - SLIDING_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

        # update recent queries list for unique-subdomain-rate detection
        self.recent_queries.append((timestamp, base_dom, qname))
        # drop old
        while self.recent_queries and self.recent_queries[0][0] < cutoff:
            self.recent_queries.popleft()

        # evaluate unique-subdomain rate for this base domain
        entries = [e for e in self.recent_queries if e[1] == base_dom]
        total = len(entries)
        unique = len(set(e[2] for e in entries))
        rate = None
        if total >= MIN_QUERIES_FOR_RATE:
            rate = unique / total
        return {
            'base_domain': base_dom,
            'queries_in_window': len(dq),
            'unique_subdomain_rate': rate,
            'total_recent_for_base': total,
            'unique_recent_for_base': unique
        }

    def process_query(self, qname: str, src_ip=None, dst_ip=None, timestamp=None):
        if timestamp is None:
            timestamp = time.time()
        score, features = self.score_domain(qname)
        rate_info = self.update_counters_and_check_rate(qname, timestamp)

        suspicion = False
        reasons = []

        # Heuristic checks that produce immediate flags
        if features['entropy_label_max'] >= ENTROPY_THRESHOLD:
            reasons.append(f"high_label_entropy={features['entropy_label_max']:.2f}")
        if features['longest_label'] >= LONG_LABEL_LEN:
            reasons.append(f"long_label_len={features['longest_label']}")
        if features['base64_like_any']:
            reasons.append("base64_like_label")
        if features['label_count'] - 1 >= SUBDOMAIN_DEPTH:
            reasons.append(f"deep_subdomain_depth={features['label_count']-1}")
        if features['domain_len'] >= DOMAIN_LEN_THRESHOLD:
            reasons.append(f"long_domain_len={features['domain_len']}")
        if features['uncommon_tld']:
            reasons.append(f"uncommon_tld")

        # Unique subdomain rate check (if we got enough data)
        if rate_info and rate_info['unique_subdomain_rate'] is not None:
            if rate_info['unique_subdomain_rate'] >= UNIQUE_SUBDOMAIN_RATE:
                reasons.append(f"high_unique_subdomain_rate={rate_info['unique_subdomain_rate']:.2f}")
        # Also check number of queries to same base in window
        if rate_info and rate_info['queries_in_window'] >= 100:
            reasons.append(f"high_query_volume={rate_info['queries_in_window']}")

        if score >= SCORE_ALERT_THRESHOLD or reasons:
            suspicion = True

        alert = None
        if suspicion:
            alert = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'qname': qname,
                'score': score,
                'features': features,
                'rate_info': rate_info,
                'reasons': reasons
            }
        return alert

# ---------- Packet handling ----------
detector = DNSTunnelDetector()

def handle_packet(pkt):
    try:
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # DNS query (qr=0)
            dns = pkt.getlayer(DNS)
            # take first question (most DNS queries have one)
            if dns.qdcount >= 1:
                q = dns.qd
                qname = q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname)
                src_ip = pkt[IP].src if IP in pkt else None
                dst_ip = pkt[IP].dst if IP in pkt else None
                timestamp = pkt.time if hasattr(pkt, 'time') else time.time()
                alert = detector.process_query(qname, src_ip, dst_ip, timestamp)
                if alert:
                    # print alert (could be logged, emailed, sent to SIEM)
                    print_alert(alert)
    except Exception as e:
        print(f"[!] Error handling packet: {e}")

def print_alert(alert: dict):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert['timestamp']))
    print("="*70)
    print(f"[ALERT] Suspicious DNS activity detected at {ts}")
    print(f"Query: {alert['qname']}")
    if alert['src_ip']:
        print(f"Source IP: {alert['src_ip']} -> Dest IP: {alert['dst_ip']}")
    print(f"Score: {alert['score']:.3f}")
    if alert['reasons']:
        print("Reasons:", ", ".join(alert['reasons']))
    f = alert['features']
    print(f"Domain len: {f['domain_len']}, labels: {f['label_count']}, longest_label: {f['longest_label']}")
    print(f"Entropy (full): {f['entropy_full']:.3f}, max_label_entropy: {f['entropy_label_max']:.3f}")
    if alert['rate_info']:
        ri = alert['rate_info']
        print(f"Base domain: {ri['base_domain']}, queries_in_window: {ri['queries_in_window']}")
        if ri['unique_subdomain_rate'] is not None:
            print(f"Unique-subdomain-rate: {ri['unique_subdomain_rate']:.3f} (total {ri['total_recent_for_base']})")
    print("="*70)

# ---------- Running modes ----------
def run_live(interface=None, count=0, timeout=None, filter_expr="udp port 53"):
    print("[*] Starting live capture for DNS queries...")
    try:
        sniff(iface=interface, filter=filter_expr, prn=handle_packet, store=0, count=count, timeout=timeout)
    except PermissionError:
        print("You need elevated privileges to sniff packets. Try running with sudo/Administrator.")
    except Exception as e:
        print(f"Sniffing error: {e}")

def run_pcap(pcap_file):
    print(f"[*] Reading pcap file: {pcap_file}")
    packets = rdpcap(pcap_file)
    for pkt in packets:
        handle_packet(pkt)

# ---------- Simple CSV export helper ----------
def process_pcap_to_csv(pcap_file, out_csv="dns_features.csv"):
    rows = []
    packets = rdpcap(pcap_file)
    for pkt in packets:
        try:
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                dns = pkt.getlayer(DNS)
                if dns.qdcount >= 1:
                    q = dns.qd
                    qname = q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname)
                    score, features = detector.score_domain(qname)
                    row = {
                        'timestamp': pkt.time,
                        'qname': qname,
                        'score': score,
                        'domain_len': features['domain_len'],
                        'label_count': features['label_count'],
                        'longest_label': features['longest_label'],
                        'entropy_full': features['entropy_full'],
                        'entropy_label_max': features['entropy_label_max'],
                        'base64_like_any': features['base64_like_any']
                    }
                    rows.append(row)
        except Exception as e:
            pass
    # write csv
    with open(out_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else ['timestamp','qname','score'])
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"Wrote features to {out_csv} ({len(rows)} rows)")

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="DNS tunneling heuristic detector")
    ap.add_argument("--pcap", "-r", help="PCAP file to analyze", type=str)
    ap.add_argument("--interface", "-i", help="Interface for live sniffing", type=str, default=None)
    ap.add_argument("--count", help="Number of packets to capture (0 = unlimited)", type=int, default=0)
    ap.add_argument("--timeout", help="Timeout (seconds) for live capture", type=int, default=None)
    ap.add_argument("--export-csv", help="Export features from pcap to CSV (use with --pcap)", action='store_true')
    args = ap.parse_args()

    if args.pcap:
        if args.export_csv:
            process_pcap_to_csv(args.pcap)
        else:
            run_pcap(args.pcap)
    else:
        # live sniffing
        run_live(interface=args.interface, count=args.count, timeout=args.timeout)

if __name__ == "__main__":
    main()
