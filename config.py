"""
Configuration settings for the Smart Firewall & Intrusion Detection System.
Covers packet capture, detection rules, ML models, decision engine,
Telegram alerts, and dashboard settings.
"""

import os

# ============================================================
# Flask Settings
# ============================================================
SECRET_KEY = os.environ.get('SECRET_KEY', 'netguard-secret-key-2026')
DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
PORT = int(os.environ.get('FLASK_PORT', 5050))

# ============================================================
# Packet Capture Settings
# ============================================================
CAPTURE_INTERFACE = os.environ.get('CAPTURE_INTERFACE', None)  # None = default interface
CAPTURE_FILTER = os.environ.get('CAPTURE_FILTER', '')  # BPF filter
PACKET_BUFFER_SIZE = 1000  # Max packets to keep in memory
CAPTURE_TIMEOUT = 0  # 0 = continuous capture

# ============================================================
# IP Whitelist & Safe Traffic Settings
# ============================================================
# Private / internal IP prefixes — never flag or block these
PRIVATE_IP_PREFIXES = (
    '192.168.',
    '10.',
    '127.',
    '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.',
    '172.24.', '172.25.', '172.26.', '172.27.',
    '172.28.', '172.29.', '172.30.', '172.31.',
)

# Explicitly whitelisted external IPs (known safe services)
WHITELISTED_IPS = {
    '1.1.1.1',          # Cloudflare DNS
    '1.0.0.1',          # Cloudflare DNS secondary
    '8.8.8.8',          # Google DNS
    '8.8.4.4',          # Google DNS secondary
    '208.67.222.222',   # OpenDNS
    '208.67.220.220',   # OpenDNS secondary
    '9.9.9.9',          # Quad9 DNS
}

# ============================================================
# Detection Settings
# ============================================================
ALERT_HISTORY_SIZE = 500  # Max alerts to keep in memory
DETECTION_WINDOW = 60  # Time window in seconds for flow analysis

# ── Port Scan Detection (sliding window) ──────────────────────
PORT_SCAN_UNIQUE_PORTS = 20    # Unique dst ports to trigger alert
PORT_SCAN_WINDOW_SEC = 5       # Sliding window in seconds

# ── Rate-based DDoS / Scan Fallback ───────────────────────────
RATE_PPS_THRESHOLD = 100       # Packets per second to flag
RATE_WINDOW_SEC = 3            # Sustain window in seconds

# ── Safety Filters ────────────────────────────────────────────
IGNORE_LOOPBACK = True         # Skip 127.0.0.1
IGNORE_BROADCAST_MULTICAST = True  # Skip 255.255.255.255, 224.* etc.
FLOW_TIMEOUT = 120  # Flow inactivity timeout in seconds

# ============================================================
# ML Model Settings
# ============================================================
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'models')
RETRAIN_INTERVAL = 3600  # Retrain model every hour (seconds)
MIN_SAMPLES_FOR_TRAINING = 1000  # Minimum samples before ML kicks in

# XGBoost classification labels
ATTACK_CLASSES = [
    'Normal',
    'DDoS',
    'Ransomware',
    'APT',
    'SQL Injection',
    'Brute Force',
]

# ============================================================
# Rule-Based Detection Thresholds
# ============================================================
RULES = {
    'port_scan': {
        'threshold': 15,       # Number of unique ports in time window
        'time_window': 10,     # Seconds
        'severity': 'high',
    },
    'syn_flood': {
        'threshold': 100,      # SYN packets per second
        'time_window': 5,
        'severity': 'critical',
    },
    'ddos': {
        'packet_rate_threshold': 200,  # Packets per second from same IP
        'byte_rate_threshold': 10485760,  # 10 MB/s from same IP
        'time_window': 10,
        'sustained_seconds': 5,  # Must be sustained for this many seconds
        'severity': 'critical',
    },
    'sql_injection': {
        'patterns': [
            "' OR '1'='1",
            "'; DROP TABLE",
            "' UNION SELECT",
            "1=1--",
            "' OR 1=1--",
            "admin'--",
            "SELECT * FROM",
            "INSERT INTO",
            "DELETE FROM",
            "UPDATE SET",
            "EXEC xp_",
            "' AND '1'='1",
            "OR 1=1",
            "UNION ALL SELECT",
            "/*!",
            "' OR ''='",
            "1' OR '1",
            "' OR 'x'='x",
            "<script>",
            "javascript:",
        ],
        'target_ports': [80, 443, 8080, 8443, 3306, 5432, 1433],
        'severity': 'critical',
    },
    'dns_tunneling': {
        'query_length_threshold': 50,  # Suspicious DNS query length
        'frequency_threshold': 30,     # Queries per minute to same domain
        'severity': 'high',
    },
    'icmp_flood': {
        'threshold': 50,       # ICMP packets per second
        'time_window': 5,
        'severity': 'medium',
    },
    'arp_spoofing': {
        'duplicate_threshold': 3,   # Same IP with different MACs (lowered for accuracy)
        'time_window': 60,          # Wider window to catch real spoofing
        'severity': 'critical',
    },
    'brute_force': {
        'threshold': 10,       # Failed connections per minute
        'time_window': 60,
        'severity': 'high',
        'target_ports': [22, 23, 3389, 21, 3306, 5432],
    },
    'large_transfer': {
        'threshold': 104857600,  # 100 MB
        'severity': 'medium',
    },
    'unusual_port': {
        'known_ports': list(range(0, 1024)) + [3306, 5432, 6379, 8080, 8443, 27017],
        'severity': 'low',
    },
    'encrypted_anomaly': {
        'cert_age_threshold': 30,       # Days - suspicious if cert is very new
        'ja3_blacklist': [],             # Known malicious JA3 hashes
        'tls_version_min': 0x0303,      # Minimum TLS 1.2
        'repetition_threshold': 5,      # Must see deprecated TLS this many times before alerting
        'severity': 'medium',
    },
}

# ============================================================
# Decision Engine / Firewall Settings
# ============================================================
FIREWALL = {
    'block_duration': 300,                # Seconds to block an IP (5 minutes)
    'flag_threshold': 1,                  # Number of FLAG events before auto-BLOCK (lowered for demo)
    'min_ml_confidence': 0.3,             # Minimum ML confidence for decisions (lowered for demo)
    'enable_iptables': False,             # Set True for real iptables integration (Linux only)
    'min_packet_count_before_action': 10, # Minimum packets from an IP before BLOCK/FLAG
}

# ============================================================
# Telegram Alert Settings
# ============================================================
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
TELEGRAM_ALERT_COOLDOWN = 30  # Seconds between alerts of same type

# ============================================================
# Protocol Colors for Dashboard
# ============================================================
PROTOCOL_COLORS = {
    'TCP': '#6366f1',
    'UDP': '#06b6d4',
    'ICMP': '#f59e0b',
    'DNS': '#10b981',
    'HTTP': '#8b5cf6',
    'HTTPS': '#ec4899',
    'ARP': '#ef4444',
    'SSH': '#14b8a6',
    'FTP': '#f97316',
    'OTHER': '#64748b',
}
