"""
Prevention and Alerting Module
Blocks suspicious domains/IPs and sends alerts (console, email, Telegram placeholder).
"""
import os
import re

ALERT_LOG = "../prevention/alerts.log"
BLOCKED_LOG = "../prevention/blocked.log"
BLOCKLIST_FILE = "../prevention/blocklist.txt"

# Placeholder for actual blocking (e.g., iptables)
def block_domain_ip(domain_or_ip):
    print(f"Blocking {domain_or_ip} (simulated)")
    with open(BLOCKED_LOG, "a") as f:
        f.write(f"Blocked: {domain_or_ip}\n")

# Placeholder for sending alerts
def send_alert(message):
    print(f"ALERT: {message}")
    # Integrate with email/Telegram API here


def process_alerts():
    if not os.path.exists(ALERT_LOG):
        print("No alerts to process.")
        return
    with open(ALERT_LOG) as f:
        for line in f:
            match = re.search(r"query': '([^']+)'", line)
            if match:
                domain = match.group(1)
                block_domain_ip(domain)
            send_alert(line.strip())

def process_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        print("No blocklist found.")
        return
    with open(BLOCKLIST_FILE) as f:
        for domain in f:
            block_domain_ip(domain.strip())
            send_alert(f"Blocked: {domain.strip()} (from blocklist)")

if __name__ == "__main__":
    process_alerts()
    process_blocklist()
