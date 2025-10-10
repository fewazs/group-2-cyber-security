"""
DNS Traffic Capture and Analysis
Uses Scapy to capture DNS packets and extract features for tunneling detection.
"""
from scapy.all import sniff
from scapy.layers.dns import DNSQR
from scapy.layers.inet import IP
import time
import json
import argparse

CAPTURE_DURATION = 5 
OUTPUT_FILE = "/home/noname/Desktop/dns tunneling prevention v2/group-2-cyber-security/capture/dns_traffic.json"
ALL_OUTPUT_FILE = "/home/noname/Desktop/dns tunneling prevention v2/group-2-cyber-security/capture/all_traffic.json"

features = []
all_features = []


def process_packet(packet):
    if packet.haslayer(DNSQR):
        timestamp = time.time()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        query = packet[DNSQR].qname.decode()
        query_len = len(query)
        pkt_size = len(packet)
        features.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "query": query,
            "query_len": query_len,
            "pkt_size": pkt_size
        })


def process_all_packet(packet):
    timestamp = time.time()
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    proto = packet.name
    pkt_size = len(packet)
    all_features.append({
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "pkt_size": pkt_size
    })


def process_combined_packet(packet):
    # DNS features
    if packet.haslayer(DNSQR):
        timestamp = time.time()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        query = packet[DNSQR].qname.decode()
        query_len = len(query)
        pkt_size = len(packet)
        features.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "query": query,
            "query_len": query_len,
            "pkt_size": pkt_size
        })
    # All traffic features
    timestamp = time.time()
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    proto = packet.name
    pkt_size = len(packet)
    all_features.append({
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "pkt_size": pkt_size
    })


def capture_dns():
    print(f"Capturing DNS traffic for {CAPTURE_DURATION} seconds...")
    sniff(filter="udp port 53", prn=process_packet, store=0, timeout=CAPTURE_DURATION)
    print(f"Captured {len(features)} DNS packets.")
    with open(OUTPUT_FILE, "w") as f:
        json.dump(features, f, indent=2)
    print(f"Features saved to {OUTPUT_FILE}")


def continuous_capture():
    while True:
        print(f"[Loop] Capturing DNS traffic for {CAPTURE_DURATION} seconds...")
        sniff(filter="udp port 53", prn=process_packet, store=0, timeout=CAPTURE_DURATION)
        print(f"[Loop] Captured {len(features)} DNS packets.")
        with open(OUTPUT_FILE, "w") as f:
            json.dump(features, f, indent=2)
        print(f"[Loop] Features saved to {OUTPUT_FILE}")
        time.sleep(5)  # Wait 5 seconds before next capture


def capture_all():
    print(f"Capturing ALL network traffic for {CAPTURE_DURATION} seconds...")
    sniff(prn=process_all_packet, store=0, timeout=CAPTURE_DURATION)
    print(f"Captured {len(all_features)} packets.")
    with open(ALL_OUTPUT_FILE, "w") as f:
        json.dump(all_features, f, indent=2)
    print(f"All traffic saved to {ALL_OUTPUT_FILE}")


def continuous_capture_all():
    while True:
        print(f"[Loop] Capturing ALL network traffic for {CAPTURE_DURATION} seconds...")
        sniff(prn=process_all_packet, store=0, timeout=CAPTURE_DURATION)
        print(f"[Loop] Captured {len(all_features)} packets.")
        with open(ALL_OUTPUT_FILE, "w") as f:
            json.dump(all_features, f, indent=2)
        print(f"[Loop] All traffic saved to {ALL_OUTPUT_FILE}")
        time.sleep(5)


def continuous_capture_combined():
    while True:
        print(f"[Loop] Capturing ALL network traffic for {CAPTURE_DURATION} seconds...")
        sniff(prn=process_combined_packet, store=0, timeout=CAPTURE_DURATION)
        print(f"[Loop] Captured {len(features)} DNS packets.")
        print(f"[Loop] Captured {len(all_features)} total packets.")
        with open(OUTPUT_FILE, "w") as f:
            json.dump(features, f, indent=2)
        with open(ALL_OUTPUT_FILE, "w") as f:
            json.dump(all_features, f, indent=2)
        print(f"[Loop] Features saved to {OUTPUT_FILE} and {ALL_OUTPUT_FILE}")
        time.sleep(1)


if __name__ == "__main__":
    continuous_capture_combined()
