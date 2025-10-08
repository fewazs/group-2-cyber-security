# DNS Monitoring Tool - Detailed Usage Guide

This document provides a comprehensive guide to using the DNS capture scripts, Admin Dashboard, and test data.

---

## 1. Capture DNS Traffic (Python)

**File:** `capture/dns_capture.py`

**Purpose:**  
Captures DNS queries and responses from your network in real-time and saves them as a JSON file for analysis and visualization.

**Steps:**
1. **Install dependencies:**  
   ```bash
   pip install scapy
