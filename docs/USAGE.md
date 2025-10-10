# DNS Tunneling Prevention and Alert System Documentation

## Overview
This system detects and prevents DNS tunneling attacks using pattern-based analysis, real-time alerts, and a monitoring dashboard.

## Components
- **capture/dns_capture.py**: Captures DNS packets and extracts features.
- **detection/dns_detection.py**: Applies detection rules to identify tunneling.
- **prevention/prevent_and_alert.py**: Blocks suspicious domains/IPs and sends alerts.
- **dashboard/app.py**: Flask backend for dashboard API.
- **test_data/dns_test_data.json**: Example DNS traffic data for testing.

## Usage
1. Run `dns_capture.py` to capture DNS traffic.
2. Run `dns_detection.py` to analyze and detect tunneling.
3. Run `prevent_and_alert.py` to block and alert on suspicious activity.
4. Start the Flask dashboard with `python dashboard/app.py`.

## Customization
- Detection thresholds and rules can be adjusted in `dns_detection.py`.
- Prevention actions (blocking, alerting) can be integrated with real firewall and notification systems.

## Requirements
- Python 3.x
- Scapy
- Flask

## Testing
Use the sample data in `test_data/dns_test_data.json` to simulate detection and prevention.

## License
Open-source for educational and research purposes.
