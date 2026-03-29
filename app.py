"""
NetGuard - Smart Firewall & Intrusion Detection System (IDS)
Flask application with SocketIO for real-time communication.

Features:
  - Real-time packet capture (Scapy)
  - Rule-based detection (DDoS, Port Scan, Brute Force, SQL Injection, etc.)
  - ML-based detection (XGBoost classification + Isolation Forest anomaly)
  - Decision Engine (BLOCK / FLAG / ALLOW)
  - Simulated firewall (IP blocking & forwarding)
  - Telegram alerts for high-severity attacks
  - Real-time dashboard with Chart.js visualizations
"""

import time
import json
import threading
from datetime import datetime

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

import config
from engine.packet_capture import PacketCaptureEngine
from detection.hybrid_detector import HybridDetector


# Initialize Flask app
app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
app.config['SECRET_KEY'] = config.SECRET_KEY

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize core components
capture_engine = PacketCaptureEngine()
hybrid_detector = HybridDetector()

# Packet counter for throttling WebSocket updates
_ws_packet_counter = 0
_ws_throttle = 3  # Send every Nth packet to websocket


def on_packet_captured(pkt_info):
    """Callback when a packet is captured."""
    global _ws_packet_counter

    # Process through detection engine
    hybrid_detector.process_packet(pkt_info)

    # Send to WebSocket (throttled)
    _ws_packet_counter += 1
    if _ws_packet_counter % _ws_throttle == 0:
        try:
            socketio.emit('new_packet', pkt_info.to_dict(), namespace='/')
        except Exception:
            pass


def on_alert_generated(alert):
    """Callback when an alert is generated."""
    try:
        socketio.emit('new_alert', alert.to_dict(), namespace='/')
    except Exception:
        pass


def on_firewall_decision(decision):
    """Callback when a firewall decision is made (BLOCK/FLAG)."""
    try:
        if decision.action in ('BLOCK', 'FLAG'):
            socketio.emit('firewall_decision', decision.to_dict(), namespace='/')
    except Exception:
        pass


# Register callbacks
capture_engine.register_callback(on_packet_captured)
hybrid_detector.register_alert_callback(on_alert_generated)
hybrid_detector.register_decision_callback(on_firewall_decision)


# ============================================================
# Routes
# ============================================================

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    """Get system status."""
    return jsonify({
        'capture_running': capture_engine.is_running,
        'capture_stats': capture_engine.get_stats(),
        'detection_stats': hybrid_detector.get_stats(),
        'server_time': time.time(),
        'uptime': time.time() - capture_engine.stats.get('start_time', time.time()),
    })


@app.route('/api/packets')
def api_packets():
    """Get recent packets."""
    count = request.args.get('count', 50, type=int)
    packets = capture_engine.get_recent_packets(count)
    return jsonify(packets)


@app.route('/api/alerts')
def api_alerts():
    """Get alerts."""
    count = request.args.get('count', 50, type=int)
    severity = request.args.get('severity', None)
    alerts = hybrid_detector.get_all_alerts(count, severity)
    return jsonify(alerts)


@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def api_acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    success = hybrid_detector.acknowledge_alert(alert_id)
    return jsonify({'success': success})


@app.route('/api/flows')
def api_flows():
    """Get active flows."""
    flows = hybrid_detector.flow_analyzer.get_active_flows_summary()
    return jsonify(flows)


@app.route('/api/normal-traffic')
def api_normal_traffic():
    """Get normal (clean) traffic summary."""
    return jsonify(hybrid_detector.get_normal_traffic_summary())


@app.route('/api/stats')
def api_stats():
    """Get capture and detection statistics."""
    return jsonify({
        'capture': capture_engine.get_stats(),
        'detection': hybrid_detector.get_stats(),
        'protocol_colors': config.PROTOCOL_COLORS,
    })


@app.route('/api/interfaces')
def api_interfaces():
    """Get available network interfaces."""
    interfaces = capture_engine.get_available_interfaces()
    return jsonify(interfaces)


@app.route('/api/capture/start', methods=['POST'])
def api_start_capture():
    """Start packet capture."""
    if not capture_engine.is_running:
        capture_engine.start()
    return jsonify({'status': 'started'})


@app.route('/api/capture/stop', methods=['POST'])
def api_stop_capture():
    """Stop packet capture."""
    capture_engine.stop()
    return jsonify({'status': 'stopped'})


@app.route('/api/ml/status')
def api_ml_status():
    """Get ML detector status."""
    return jsonify(hybrid_detector.ml_detector.get_status())


@app.route('/api/ml/retrain', methods=['POST'])
def api_ml_retrain():
    """Force retrain ML model."""
    hybrid_detector.ml_detector.retrain()
    return jsonify({'status': 'retraining started'})


# ============================================================
# Firewall API Endpoints
# ============================================================

@app.route('/api/firewall/status')
def api_firewall_status():
    """Get firewall status including blocked/flagged IPs."""
    return jsonify(hybrid_detector.get_firewall_status())


@app.route('/api/firewall/blocked')
def api_blocked_ips():
    """Get currently blocked IPs."""
    return jsonify(hybrid_detector.decision_engine.get_blocked_ips())


@app.route('/api/firewall/flagged')
def api_flagged_ips():
    """Get currently flagged IPs."""
    return jsonify(hybrid_detector.decision_engine.get_flagged_ips())


@app.route('/api/firewall/decisions')
def api_firewall_decisions():
    """Get recent firewall decisions."""
    count = request.args.get('count', 50, type=int)
    return jsonify(hybrid_detector.decision_engine.get_recent_decisions(count))


@app.route('/api/firewall/block/<ip>', methods=['POST'])
def api_block_ip(ip):
    """Manually block an IP address."""
    req_data = request.get_json() or {}
    reason = req_data.get('reason', 'Manually blocked via dashboard')
    success = hybrid_detector.decision_engine.block_ip(ip, reason)
    return jsonify({'success': success})

@app.route('/api/firewall/unblock/<ip>', methods=['POST'])
def api_unblock_ip(ip):
    """Unblock an IP address."""
    success = hybrid_detector.unblock_ip(ip)
    return jsonify({'success': success, 'ip': ip})


# ============================================================
# WebSocket Events
# ============================================================

@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection."""
    print(f"[*] Client connected")
    emit('status', {
        'capture_running': capture_engine.is_running,
        'message': 'Connected to NetGuard Smart Firewall & IDS'
    })


@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    print(f"[*] Client disconnected")


@socketio.on('start_capture')
def handle_start_capture():
    """Start capture via WebSocket."""
    if not capture_engine.is_running:
        capture_engine.start()
    emit('status', {'capture_running': True, 'message': 'Capture started'})


@socketio.on('stop_capture')
def handle_stop_capture():
    """Stop capture via WebSocket."""
    capture_engine.stop()
    emit('status', {'capture_running': False, 'message': 'Capture stopped'})


# ============================================================
# Start background stats updater
# ============================================================

def stats_updater():
    """Periodically send stats to all connected clients."""
    while True:
        time.sleep(2)
        try:
            stats = {
                'capture': capture_engine.get_stats(),
                'detection': hybrid_detector.get_stats(),
            }
            socketio.emit('stats_update', stats, namespace='/')
        except Exception:
            pass


stats_thread = threading.Thread(target=stats_updater, daemon=True, name='StatsUpdater')
stats_thread.start()


# ============================================================
# Main
# ============================================================

if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗  ║
    ║     ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗ ║
    ║     ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║ ║
    ║     ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║ ║
    ║     ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║ ║
    ║     ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ║
    ║                                                           ║
    ║       Smart Firewall & Intrusion Detection System         ║
    ║         Hybrid Detection Engine v2.0 (IDS/IPS)            ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    # Auto-start capture
    capture_engine.start()

    print(f"[*] Dashboard: http://localhost:{config.PORT}")
    print(f"[*] API docs:  http://localhost:{config.PORT}/api/status")
    print(f"[*] Firewall:  http://localhost:{config.PORT}/api/firewall/status")

    socketio.run(app, host=config.HOST, port=config.PORT, debug=config.DEBUG,
                 allow_unsafe_werkzeug=True)
