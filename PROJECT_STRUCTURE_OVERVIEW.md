# DNS Tunneling Prevention Project Structure Overview

This document explains the purpose of each major file and folder in your project, organized by functional division.

---

## 1. Frontend (React Dashboard)
- **dashboard/react-frontend/**: Contains the React app for the live dashboard.
  - `App.js`, `index.js`, `index.css`: Main React components and styles.
  - `public/index.html`: HTML template for the dashboard.
  - `package.json`: Manages React dependencies and sets up a proxy to the backend.

---

## 2. Backend (Flask API)
- **dashboard/app.py**: Flask server providing API endpoints for the dashboard to fetch detection and alert data.

---

## 3. DNS Capture
- **capture/dns_capture.py**: Continuously captures DNS packets from the network and saves them to `dns_traffic.json`.
- **capture/dns_traffic.json**: Stores captured DNS traffic data.

---

## 4. Detection
- **detection/dns_detection.py**: Continuously analyzes captured DNS traffic for tunneling patterns and generates alerts.

---

## 5. Prevention & Alerts
- **prevention/prevent_and_alert.py**: Reads alerts and takes action to block suspicious domains.
- **prevention/alerts.log**: Log file for alerts and prevention actions.
- **prevention/simulate_alerts.py**: Simulates alerts for testing the prevention system.

---

## 6. Utilities & Data
- **Entropy.py**: Utility for calculating entropy, used in detection logic.
- **dns_tunnel_security.py**: Main script or entry point for the overall system (if used).
- **test_data/dns_test_data.json**: Sample DNS traffic data for testing.
- **test_data/copy_test_data.py**: Script to copy test data for simulation.

---

## 7. Documentation
- **README.md**: Project overview and setup instructions.
- **docs/USAGE.md**: Detailed usage guide.

---

### Summary Table

| Division         | Files/Folders                                      | Purpose                                      |
|------------------|----------------------------------------------------|----------------------------------------------|
| Frontend         | dashboard/react-frontend/                          | User dashboard (React)                       |
| Backend          | dashboard/app.py                                   | API server (Flask)                           |
| Capture          | capture/dns_capture.py, dns_traffic.json           | DNS packet capture                           |
| Detection        | detection/dns_detection.py                         | DNS tunneling detection                      |
| Prevention/Alert | prevention/prevent_and_alert.py, alerts.log, simulate_alerts.py | Alert handling and prevention                |
| Utilities/Data   | Entropy.py, dns_tunnel_security.py, test_data/     | Helper scripts and test data                 |
| Documentation    | README.md, docs/USAGE.md                           | Project documentation                        |

---

Let me know if you want a more detailed explanation for any specific file or logic!