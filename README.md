# group-2-cyber-security
DNS Tunneling Prevention and Alert System

1. Project Title
DNS Tunneling Prevention and Alert System

2. Background and Problem Statement
In Ethiopia, internet service providers (ISPs) often provide social media bundles such as Facebook, TikTok, and Spotify. However, malicious users exploit tools like MTM Tunnel, HTTP Injector, and DNS tunneling to disguise unauthorized traffic as legitimate bundle traffic. This allows them to bypass restrictions and use other services (e.g., YouTube, Telegram) without paying, causing financial loss to ISPs, unfair usage, and potential cybersecurity risks.

Traditional firewalls and filtering systems cannot easily detect this type of tunneling because the malicious traffic is hidden inside DNS queries and responses. Thus, there is a strong need for a dedicated DNS Tunneling Prevention and Alert System.

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

Wireshark / Zeek / Suricata → Packet capture and traffic analysis
Python (Scapy, dnslib, socket) → Detection logic implementation
Flask / React → Monitoring dashboard
iptables / pfSense → Blocking prevention mechanism
Linux environment (Kali) → Testing and deployment
7. Expected Outcomes
A working prototype system that detects and prevents DNS tunneling.
Documentation of DNS tunneling behavior in Ethiopian ISP bundle usage.
Real-time alerts and prevention for malicious DNS usage.
Contribution to cybersecurity defense mechanisms against tunneling-based attacks.

8. Deliverables

1. Research document (PDF report).
2. Source code (GitHub repository).
3. DNS tunneling test datasets.
4. Prototype system with live alerts.
5. Presentation slides for defense.

9. Timeline (Estimated – 15 Days)
Day 1–3: Research and traffic capture
Day 4–6: Analysis and rule creation
Day 7–10: System implementation (detection + prevention)
Day 11–13: Dashboard & alert system
Day 14: Testing & documentation
Day 15: Final submission & presentation

10. Conclusion

This project will deliver a practical security tool to detect and prevent DNS tunneling attacks that exploit bundle-based internet services. By implementing this system, ISPs and organizations can ensure fair internet usage, prevent financial loss, and strengthen cybersecurity resilience in Ethiopia.


---
