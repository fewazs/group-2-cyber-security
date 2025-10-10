"""
Flask Backend for DNS Monitoring Dashboard
Provides API endpoints for DNS stats, alerts, and blocked domains.
"""
from flask import Flask, jsonify, request, session, send_file
from flask_cors import CORS
import json
import os
import time
import subprocess
from threading import Thread

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
CORS(app, supports_credentials=True)

BLOCKLIST_FILE = '../prevention/blocklist.txt'
SUSPEND_FILE = '../prevention/suspend.json'
DEVICES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../prevention/devices.json')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DNS_TRAFFIC_PATH = os.path.join(BASE_DIR, '../capture/dns_traffic.json')
ALL_TRAFFIC_PATH = os.path.join(BASE_DIR, '../capture/all_traffic.json')

capture_process = None
capture_filename = None

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    # Simple hardcoded authentication for demo
    if username == 'admin' and password == 'password':
        session['logged_in'] = True
        return jsonify({'success': True})
    return jsonify({'success': False}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    return jsonify({'success': True})

@app.route('/stats')
def stats():
    stats = {
        'real_spotify': 0,
        'fake_spotify': 0,
        'alerts': 0
    }
    stats_path = os.path.join(BASE_DIR, '../prevention/spotify_stats.json')
    if os.path.exists(stats_path):
        with open(stats_path) as f:
            stats.update(json.load(f))
    return jsonify(stats)

@app.route('/alerts')
def alerts():
    alerts = []
    if os.path.exists('../prevention/alerts.log'):
        with open('../prevention/alerts.log') as f:
            alerts = [line.strip() for line in f.readlines()[-10:]]
    return jsonify(alerts)

@app.route('/admin/block', methods=['POST'])
def admin_block():
    data = request.get_json()
    domain = data.get('domain')
    if domain:
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(domain + '\n')
        return jsonify({'success': True, 'action': 'blocked', 'domain': domain})
    return jsonify({'success': False}), 400

@app.route('/admin/unblock', methods=['POST'])
def admin_unblock():
    data = request.get_json()
    domain = data.get('domain')
    if domain and os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE) as f:
            lines = f.readlines()
        with open(BLOCKLIST_FILE, 'w') as f:
            for line in lines:
                if line.strip() != domain:
                    f.write(line)
        return jsonify({'success': True, 'action': 'unblocked', 'domain': domain})
    return jsonify({'success': False}), 400

@app.route('/admin/suspend', methods=['POST'])
def admin_suspend():
    data = request.get_json()
    domain = data.get('domain')
    duration = data.get('duration')  # seconds
    if domain and duration:
        suspend = {}
        if os.path.exists(SUSPEND_FILE):
            with open(SUSPEND_FILE) as f:
                suspend = json.load(f)
        suspend[domain] = time.time() + int(duration)
        with open(SUSPEND_FILE, 'w') as f:
            json.dump(suspend, f)
        return jsonify({'success': True, 'action': 'suspended', 'domain': domain, 'until': suspend[domain]})
    return jsonify({'success': False}), 400

@app.route('/admin/devices')
def admin_devices():
    devices = []
    if os.path.exists(DEVICES_PATH):
        with open(DEVICES_PATH) as f:
            devices = json.load(f)
    return jsonify({'devices': devices})

@app.route('/api/dns-stats')
def get_dns_stats():
    stats = {}
    queries = []
    try:
        if os.path.exists(DNS_TRAFFIC_PATH):
            with open(DNS_TRAFFIC_PATH) as f:
                try:
                    data = json.load(f)
                except Exception as e:
                    print(f"Error loading dns_traffic.json: {e}")
                    data = []
                stats = {
                    "total_packets": len(data),
                    "unique_domains": len(set(d.get("query") for d in data if "query" in d)),
                    "avg_query_len": sum(d.get("query_len",0) for d in data) / len(data) if data else 0
                }
                queries = data[-10:] if len(data) >= 10 else data
    except Exception as e:
        print(f"API error: {e}")
    return jsonify({"stats": stats, "queries": queries})

@app.route('/api/all-traffic')
def all_traffic():
    traffic = []
    try:
        if os.path.exists(ALL_TRAFFIC_PATH):
            with open(ALL_TRAFFIC_PATH) as f:
                try:
                    traffic = json.load(f)
                except Exception as e:
                    print(f"Error loading all_traffic.json: {e}")
                    traffic = []
            traffic = traffic[-10:] if len(traffic) >= 10 else traffic
    except Exception as e:
        print(f"API error: {e}")
    return jsonify(traffic)

@app.route('/api/capture/start', methods=['POST'])
def api_capture_start():
    global capture_process, capture_filename
    capture_filename = request.json.get('filename', f"capture_{int(time.time())}.json")
    capture_path = os.path.join(BASE_DIR, f"../capture/{capture_filename}")
    if capture_process is None or not capture_process.is_alive():
        def run_capture():
            subprocess.call(['sudo', 'python3', 'capture/dns_capture.py', '--output', capture_path])
        capture_process = Thread(target=run_capture)
        capture_process.start()
        return jsonify({'success': True, 'message': f'Capture started: {capture_filename}'})
    return jsonify({'success': False, 'message': 'Capture already running'})

@app.route('/api/capture/stop', methods=['POST'])
def api_capture_stop():
    global capture_process
    if capture_process and capture_process.is_alive():
        # Stopping a thread running a subprocess is not trivial; recommend using a flag or process management in production
        return jsonify({'success': True, 'message': 'Stop requested (manual stop required)'})
    return jsonify({'success': False, 'message': 'No capture running'})

@app.route('/api/capture/save', methods=['POST'])
def api_capture_save():
    global capture_filename
    save_as = request.json.get('filename')
    if not capture_filename:
        return jsonify({'success': False, 'message': 'No capture in progress'})
    src_path = os.path.join(BASE_DIR, f"../capture/{capture_filename}")
    dst_path = os.path.join(BASE_DIR, f"../capture/{save_as}") if save_as else src_path
    if os.path.exists(src_path):
        if save_as:
            os.rename(src_path, dst_path)
        return jsonify({'success': True, 'message': f'Capture saved as {save_as or capture_filename}'})
    return jsonify({'success': False, 'message': 'No capture file found'})

if __name__ == "__main__":
    app.run(debug=True)
