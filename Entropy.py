# Entropy and randomness detection 
# Use Shannon entropy on the subdomain portion. Below is an improved Python snippet that does live sniffing, decodes qname, computes entropy, and logs suspicious entries.

# python 3
from scapy.all import sniff, DNSQR
from collections import Counter
import math
import logging
import time

logging.basicConfig(filename='dns_tunnel_alerts.log', level=logging.INFO,
                    format='%(asctime)s %(message)s')

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((count/total) * math.log2(count/total) for count in counts.values())

def is_base_encoded(s: str) -> bool:
    # crude check for base32/base64-like characters
    return all(c.isalnum() or c in '-_=' for c in s)

def detect_dns(pkt):
    if pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode().rstrip('.')
        # separate domain / left-most label(s)
        labels = qname.split('.')
        subdomain = labels[0] if len(labels) > 2 else ''
        qlen = len(qname)
        sub_len = len(subdomain)
        entropy = shannon_entropy(subdomain)

        alerts = []
        if qlen > 150:
            alerts.append(f"Long qname ({qlen} chars)")
        if sub_len > 60:
            alerts.append(f"Long subdomain ({sub_len} chars)")
        if entropy >= 4.5 and sub_len >= 12:
            alerts.append(f"High entropy({entropy:.2f})")
        if is_base_encoded(subdomain) and sub_len >= 16:
            alerts.append("Base-like encoding detected")

        if alerts:
            logging.info("SUSPICIOUS DNS: %s | alerts=%s", qname, ";".join(alerts))
            print("[ALERT]", qname, alerts)

if __name__ == '__main__':
    # run as root or capture on mirrored traffic; filter for DNS only
    sniff(filter='udp port 53', prn=detect_dns, store=0)
