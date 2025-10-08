# capture/dns_capture.py
import json
import datetime
from scapy.all import sniff, DNS, DNSQR

# File to store captured DNS traffic
OUTPUT_FILE = "capture/all_traffic.json"

# Load existing data if file exists
try:
    with open(OUTPUT_FILE, "r") as f:
        traffic_data = json.load(f)
except FileNotFoundError:
    traffic_data = []

def capture_dns(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        entry = {
            "timestamp": timestamp,
            "query": query,
            "response": str(packet[DNS].an.rdata) if packet[DNS].ancount > 0 else None,
            "type": "A"
        }
        traffic_data.append(entry)
        print(f"Captured: {entry}")

# Start sniffing DNS packets (UDP port 53)
print("Starting DNS capture...")
sniff(filter="udp port 53", prn=capture_dns, store=0)

# Save captured traffic to JSON on exit
with open(OUTPUT_FILE, "w") as f:
    json.dump(traffic_data, f, indent=2)
