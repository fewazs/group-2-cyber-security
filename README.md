# React Frontend for DNS Dashboard

## Setup
1. Install Node.js and npm if not already installed.
2. Run the following commands:
```
cd dashboard/react-frontend
npm install
npm start
```

## Features
- View DNS traffic statistics
- View alerts and blocked domains
- Auto-refresh every 10 seconds

## API Endpoints
- `/api/dns-stats`
- `/api/alerts`
- `/api/blocked`

<<<<<<< HEAD
## Note
Ensure the Flask backend is running on port 5000 before starting the frontend.
=======
3. Objectives
General Objective
To design and implement a system that detects and prevents DNS tunneling activities in real time, ensuring secure and fair usage of internet bundles.

Specific Objectives
a) Capture and analyze DNS traffic from client devices.
b) Identify tunneling attempts based on traffic patterns, packet size, timing, and frequency.
c) Differentiate between legitimate DNS traffic (e.g., normal Spotify bundle usage) and malicious tunneling traffic (e.g., MTM Tunnel).
d) Generate real-time alerts and logs when suspicious DNS tunneling is detected.
e) Provide ISPs and administrators with a dashboard for monitoring DNS activities.

4. Scope of the Project
*Focused on DNS tunneling detection (no machine learning, purely pattern/behavior-based).
*Works with open-source tools (Wireshark, Zeek, Suricata, Scapy, Python libraries).
*Implements prevention mechanisms such as blocking suspicious domains or notifying administrators.
*Tested on Spotify bundle traffic vs MTM Tunnel traffic as a case study.
*Deliverables include documentation, source code, and a working prototype.

5. Methodology
Step 1: Traffic Capture and Analysis
=>Use Wireshark / Zeek to capture DNS packets.
=>Compare normal DNS traffic (Spotify bundle) vs tunneled DNS traffic (MTM Tunnel, HTTP Injector).
=>Extract features such as:
                         -Query length and frequency
                         -Packet size distribution
                         -Time intervals between queries
                         -Suspicious domains (randomized subdomains, base64-encoded payloads)

Step 2: Detection Rules
=>Define thresholds and anomaly-based rules:
                                         -Unusually high frequency of DNS queries per second.
                                         -Large query sizes (> 100 bytes).
                                         -Repeated queries to uncommon domains.
                                         -Implement detection in Python (Scapy + custom scripts) and/or Suricata IDS rules.
Step 3: Prevention & Alerting

If tunneling is detected:
                       -Block suspicious IP/domains via firewall rules.
                       -Send real-time alerts to admin (email/Telegram).
                       -Log activity for further analysis.

Step 4: Dashboard and Reporting
Build a simple web-based dashboard (Flask + React) to visualize:
                                         -DNS traffic statistics
                                         -Suspicious activity alerts
                                         -Logs of blocked domains
6. Tools and Technologies

Wireshark / Zeek / Suricata Detection logic implementation
Flask / React Blocking prevention mechanism
Linux environment (Kali) 15 Days)
Day 16: Analysis and rule creation
Day 713: Dashboard & alert system
Day 14: Testing & documentation
Day 15: Final submission & presentation

10. Conclusion

This project will deliver a practical security tool to detect and prevent DNS tunneling attacks that exploit bundle-based internet services. By implementing this system, ISPs and organizations can ensure fair internet usage, prevent financial loss, and strengthen cybersecurity resilience in Ethiopia.

# Setup & Testing Instructions

## 1. Install Python dependencies
```
pip install -r requirements.txt
```

## 2. Capture DNS traffic
Run as root/admin:
```
python capture/dns_capture.py
```

## 3. Run detection logic
```
python detection/dns_detection.py
```

## 4. Run prevention & alerting
```
python prevention/prevent_and_alert.py
```

## 5. Start Flask dashboard backend
```
python dashboard/app.py
```

## 6. (Optional) Use test data
Copy `test_data/dns_test_data.json` to `capture/dns_traffic.json` for simulated detection.

## 7. React Frontend Setup
See `dashboard/react-frontend/README.md` for instructions.

---
>>>>>>> 62679f3e (Add/update dns_tunnel_security.py)