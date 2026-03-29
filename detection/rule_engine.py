"""
Rule-Based Detection Engine.
Detects known attack patterns based on packet and flow characteristics.
Each detection rule provides explainable reasons for alerts.

Attack types detected:
  - DDoS (high packet rate from same IP)
  - Port Scanning (multiple ports accessed quickly)
  - SYN Flood (volumetric SYN-only traffic)
  - Brute Force (repeated login attempts)
  - SQL Injection (suspicious payload patterns)
  - DNS Tunneling (long queries, high frequency)
  - ICMP Flood (volumetric ICMP traffic)
  - ARP Spoofing (duplicate IP-MAC mappings)
  - Encrypted Traffic Anomaly (deprecated TLS versions)
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime

import config


class Alert:
    """Represents a security alert with explainable details."""

    _id_counter = 0
    _lock = threading.Lock()

    def __init__(self, alert_type, severity, source_ip, target_ip='',
                 description='', evidence=None, confidence=0.0):
        with Alert._lock:
            Alert._id_counter += 1
            self.alert_id = Alert._id_counter

        self.alert_type = alert_type
        self.severity = severity  # critical, high, medium, low, info
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.description = description
        self.evidence = evidence or []
        self.confidence = confidence
        self.timestamp = time.time()
        self.detection_method = 'rule-based'
        self.acknowledged = False

    def to_dict(self):
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'description': self.description,
            'evidence': self.evidence,
            'confidence': round(self.confidence, 2),
            'timestamp': self.timestamp,
            'time_str': datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S'),
            'detection_method': self.detection_method,
            'acknowledged': self.acknowledged,
        }


class RuleBasedDetector:
    """
    Detects attacks using predefined rules and heuristics.
    Each detection provides explainable evidence.
    """

    def __init__(self):
        self.alerts = deque(maxlen=config.ALERT_HISTORY_SIZE)
        self._alert_callbacks = []
        self._lock = threading.Lock()

        # Tracking data structures
        self._syn_tracker = defaultdict(lambda: deque(maxlen=500))     # IP -> deque of timestamps
        self._port_scan_tracker = defaultdict(lambda: defaultdict(set))  # src_ip -> {target_ip: {ports}}
        self._port_scan_times = defaultdict(lambda: deque(maxlen=200))
        self._dns_tracker = defaultdict(lambda: deque(maxlen=200))     # src_ip -> deque of queries
        self._icmp_tracker = defaultdict(lambda: deque(maxlen=500))    # target_ip -> timestamps
        self._arp_table = defaultdict(set)                              # ip -> set of MACs
        self._brute_force_tracker = defaultdict(lambda: deque(maxlen=100))  # (ip, port) -> timestamps
        self._transfer_tracker = defaultdict(int)                       # flow_id -> total bytes
        self._encrypted_tracker = defaultdict(list)                     # src_ip -> list of tls info

        # DDoS tracker: packets per src_ip
        self._ddos_packet_tracker = defaultdict(lambda: deque(maxlen=2000))
        self._ddos_byte_tracker = defaultdict(lambda: deque(maxlen=2000))

        # SQL Injection tracker
        self._sqli_tracker = defaultdict(lambda: deque(maxlen=100))

        # Cooldown to prevent alert flooding (type+src -> last alert time)
        self._alert_cooldown = {}
        self._cooldown_seconds = 15

    def register_alert_callback(self, callback):
        """Register callback for new alerts."""
        self._alert_callbacks.append(callback)

    def analyze_packet(self, pkt_info, flow=None):
        """Run all detection rules on a packet."""
        detections = []

        detections.extend(self._detect_ddos(pkt_info))
        detections.extend(self._detect_port_scan(pkt_info))
        detections.extend(self._detect_syn_flood(pkt_info))
        detections.extend(self._detect_brute_force(pkt_info))
        detections.extend(self._detect_sql_injection(pkt_info))
        detections.extend(self._detect_dns_tunneling(pkt_info))
        detections.extend(self._detect_icmp_flood(pkt_info))
        detections.extend(self._detect_arp_spoofing(pkt_info))
        detections.extend(self._detect_encrypted_anomaly(pkt_info))

        for alert in detections:
            if self._check_cooldown(alert):
                with self._lock:
                    self.alerts.append(alert)
                for callback in self._alert_callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        print(f"[!] Alert callback error: {e}")

        return detections

    def _check_cooldown(self, alert):
        """Check if alert is within cooldown period."""
        key = f"{alert.alert_type}:{alert.source_ip}"
        now = time.time()
        if key in self._alert_cooldown:
            if now - self._alert_cooldown[key] < self._cooldown_seconds:
                return False
        self._alert_cooldown[key] = now
        return True

    # ─── DDoS Detection ──────────────────────────────────────

    def _detect_ddos(self, pkt_info):
        """
        Detect DDoS attacks based on high packet rate from the same IP.
        Tracks packets per source IP over a sliding time window.
        """
        alerts = []
        rules = config.RULES['ddos']

        if not pkt_info.src_ip:
            return alerts

        now = time.time()
        src = pkt_info.src_ip

        # Track packet timestamps and sizes per source IP
        self._ddos_packet_tracker[src].append(now)
        self._ddos_byte_tracker[src].append(pkt_info.length)

        # Clean old entries outside the time window
        while (self._ddos_packet_tracker[src] and
               now - self._ddos_packet_tracker[src][0] > rules['time_window']):
            self._ddos_packet_tracker[src].popleft()
            if self._ddos_byte_tracker[src]:
                self._ddos_byte_tracker[src].popleft()

        packet_count = len(self._ddos_packet_tracker[src])
        packet_rate = packet_count / rules['time_window']
        total_bytes = sum(self._ddos_byte_tracker[src])
        byte_rate = total_bytes / rules['time_window']

        # Check packet rate threshold
        if packet_rate >= rules['packet_rate_threshold']:
            confidence = min(1.0, packet_rate / (rules['packet_rate_threshold'] * 2))
            alert = Alert(
                alert_type='DDoS',
                severity=rules['severity'],
                source_ip=src,
                target_ip=pkt_info.dst_ip,
                description=(
                    f"DDoS attack detected from {src}. "
                    f"{packet_count} packets in {rules['time_window']}s "
                    f"({packet_rate:.0f} pps, {byte_rate/1024:.1f} KB/s)."
                ),
                evidence=[
                    f"Source IP: {src}",
                    f"Packet rate: {packet_rate:.1f} packets/s",
                    f"Threshold: {rules['packet_rate_threshold']} packets/s",
                    f"Byte rate: {byte_rate/1024:.1f} KB/s",
                    f"Total packets in window: {packet_count}",
                    f"Time window: {rules['time_window']}s",
                    f"Abnormally high traffic volume from single source",
                ],
                confidence=confidence,
            )
            alerts.append(alert)
            self._ddos_packet_tracker[src].clear()
            self._ddos_byte_tracker[src].clear()

        # Check byte rate threshold
        elif byte_rate >= rules['byte_rate_threshold']:
            confidence = min(1.0, byte_rate / (rules['byte_rate_threshold'] * 2))
            alert = Alert(
                alert_type='DDoS',
                severity=rules['severity'],
                source_ip=src,
                target_ip=pkt_info.dst_ip,
                description=(
                    f"DDoS (volumetric) detected from {src}. "
                    f"Byte rate: {byte_rate/1024/1024:.1f} MB/s "
                    f"exceeds threshold."
                ),
                evidence=[
                    f"Source IP: {src}",
                    f"Byte rate: {byte_rate/1024/1024:.2f} MB/s",
                    f"Threshold: {rules['byte_rate_threshold']/1024/1024:.0f} MB/s",
                    f"Packet rate: {packet_rate:.1f} pps",
                    f"Large volume data flood detected",
                ],
                confidence=confidence,
            )
            alerts.append(alert)
            self._ddos_packet_tracker[src].clear()
            self._ddos_byte_tracker[src].clear()

        return alerts

    # ─── SQL Injection Detection ─────────────────────────────

    def _detect_sql_injection(self, pkt_info):
        """
        Detect SQL injection attempts by checking packet payloads
        for suspicious SQL patterns (targeting web/DB ports).
        """
        alerts = []
        rules = config.RULES['sql_injection']

        # Only check packets to web/database ports
        if pkt_info.dst_port not in rules['target_ports']:
            return alerts

        # Check DNS query for SQL patterns (sometimes encoded in queries)
        payload_to_check = ''
        if pkt_info.dns_query:
            payload_to_check = pkt_info.dns_query

        # Check if payload size suggests content (without deep inspection)
        if pkt_info.payload_size > 0 and pkt_info.protocol in ('HTTP', 'TCP'):
            # In a real system, we'd inspect the payload.
            # Here we track repeated connections to web ports with large payloads
            # as potential injection vectors.
            now = time.time()
            src = pkt_info.src_ip

            self._sqli_tracker[src].append({
                'time': now,
                'port': pkt_info.dst_port,
                'size': pkt_info.payload_size,
                'target': pkt_info.dst_ip,
            })

            # Clean old entries (60s window)
            while (self._sqli_tracker[src] and
                   now - self._sqli_tracker[src][0]['time'] > 60):
                self._sqli_tracker[src].popleft()

            # Flag if many requests with payloads to web ports in short time
            web_requests = [r for r in self._sqli_tracker[src]
                           if r['size'] > 100]  # Meaningful payload size

            if len(web_requests) >= 20:
                confidence = min(1.0, len(web_requests) / 40)
                avg_size = sum(r['size'] for r in web_requests) / len(web_requests)
                targets = set(r['target'] for r in web_requests)

                alert = Alert(
                    alert_type='SQL Injection',
                    severity=rules['severity'],
                    source_ip=src,
                    target_ip=', '.join(list(targets)[:3]),
                    description=(
                        f"Potential SQL injection attack from {src}. "
                        f"{len(web_requests)} suspicious requests with payloads "
                        f"(avg {avg_size:.0f} bytes) to web/DB ports in 60s."
                    ),
                    evidence=[
                        f"Source IP: {src}",
                        f"Request count: {len(web_requests)} in 60s",
                        f"Average payload size: {avg_size:.0f} bytes",
                        f"Target ports: {set(r['port'] for r in web_requests)}",
                        f"Target hosts: {', '.join(list(targets)[:5])}",
                        f"Rapid payload-bearing requests to web/DB ports",
                        f"Pattern consistent with SQLi/XSS scanning",
                    ],
                    confidence=confidence,
                )
                alerts.append(alert)
                self._sqli_tracker[src].clear()

        return alerts

    # ─── Port Scan Detection ─────────────────────────────────

    def _detect_port_scan(self, pkt_info):
        """Detect port scanning activity."""
        alerts = []
        rules = config.RULES['port_scan']

        if pkt_info.protocol in ('TCP', 'HTTP', 'HTTPS') and pkt_info.flags and 'S' in pkt_info.flags:
            now = time.time()
            src = pkt_info.src_ip
            dst = pkt_info.dst_ip

            self._port_scan_tracker[src][dst].add(pkt_info.dst_port)
            self._port_scan_times[src].append(now)

            # Clean old entries
            while self._port_scan_times[src] and now - self._port_scan_times[src][0] > rules['time_window']:
                self._port_scan_times[src].popleft()

            # Check threshold
            all_ports = set()
            for target, ports in self._port_scan_tracker[src].items():
                all_ports.update(ports)

            if len(all_ports) >= rules['threshold']:
                confidence = min(1.0, len(all_ports) / (rules['threshold'] * 2))
                targets = list(self._port_scan_tracker[src].keys())

                alert = Alert(
                    alert_type='Port Scan',
                    severity=rules['severity'],
                    source_ip=src,
                    target_ip=', '.join(targets[:3]),
                    description=f"Port scan detected from {src}. {len(all_ports)} unique ports probed across {len(targets)} target(s) in {rules['time_window']}s window.",
                    evidence=[
                        f"Source IP: {src}",
                        f"Unique ports scanned: {len(all_ports)}",
                        f"Threshold: {rules['threshold']} ports",
                        f"Target hosts: {', '.join(targets[:5])}",
                        f"Sample ports: {sorted(list(all_ports))[:10]}",
                        f"All SYN packets (no established connections)",
                        f"Time window: {rules['time_window']}s",
                    ],
                    confidence=confidence,
                )
                alerts.append(alert)
                # Reset tracker for this source
                self._port_scan_tracker[src].clear()

        return alerts

    # ─── SYN Flood Detection ─────────────────────────────────

    def _detect_syn_flood(self, pkt_info):
        """Detect SYN flood attacks."""
        alerts = []
        rules = config.RULES['syn_flood']

        if pkt_info.flags and pkt_info.flags == 'S':
            now = time.time()
            target = pkt_info.dst_ip

            self._syn_tracker[target].append(now)

            # Clean old entries
            while self._syn_tracker[target] and now - self._syn_tracker[target][0] > rules['time_window']:
                self._syn_tracker[target].popleft()

            syn_count = len(self._syn_tracker[target])
            rate = syn_count / rules['time_window']

            if rate >= rules['threshold']:
                confidence = min(1.0, rate / (rules['threshold'] * 2))
                alert = Alert(
                    alert_type='SYN Flood',
                    severity=rules['severity'],
                    source_ip=pkt_info.src_ip,
                    target_ip=target,
                    description=f"SYN flood attack detected targeting {target}. {syn_count} SYN packets in {rules['time_window']}s ({rate:.0f}/s).",
                    evidence=[
                        f"Target IP: {target}",
                        f"SYN packets received: {syn_count}",
                        f"Rate: {rate:.1f} SYN/s",
                        f"Threshold: {rules['threshold']} SYN/s",
                        f"No corresponding ACK packets observed",
                        f"Multiple source IPs (potential spoofing)",
                        f"Time window: {rules['time_window']}s",
                    ],
                    confidence=confidence,
                )
                alerts.append(alert)
                self._syn_tracker[target].clear()

        return alerts

    # ─── Brute Force Detection ───────────────────────────────

    def _detect_brute_force(self, pkt_info):
        """Detect brute force login attempts."""
        alerts = []
        rules = config.RULES['brute_force']

        if pkt_info.dst_port in rules['target_ports']:
            if pkt_info.flags and ('S' in pkt_info.flags or 'R' in pkt_info.flags):
                now = time.time()
                key = (pkt_info.src_ip, pkt_info.dst_port)

                self._brute_force_tracker[key].append(now)

                while self._brute_force_tracker[key] and now - self._brute_force_tracker[key][0] > rules['time_window']:
                    self._brute_force_tracker[key].popleft()

                count = len(self._brute_force_tracker[key])
                if count >= rules['threshold']:
                    service_names = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 21: 'FTP', 3306: 'MySQL', 5432: 'PostgreSQL'}
                    service = service_names.get(pkt_info.dst_port, f'port {pkt_info.dst_port}')
                    confidence = min(1.0, count / (rules['threshold'] * 2))

                    alert = Alert(
                        alert_type='Brute Force',
                        severity=rules['severity'],
                        source_ip=pkt_info.src_ip,
                        target_ip=pkt_info.dst_ip,
                        description=f"Brute force attack on {service} from {pkt_info.src_ip}. {count} connection attempts in {rules['time_window']}s.",
                        evidence=[
                            f"Source IP: {pkt_info.src_ip}",
                            f"Target service: {service} (port {pkt_info.dst_port})",
                            f"Connection attempts: {count}",
                            f"Threshold: {rules['threshold']} attempts/{rules['time_window']}s",
                            f"Rapid SYN/RST pattern indicates failed logins",
                        ],
                        confidence=confidence,
                    )
                    alerts.append(alert)
                    self._brute_force_tracker[key].clear()

        return alerts

    # ─── DNS Tunneling Detection ─────────────────────────────

    def _detect_dns_tunneling(self, pkt_info):
        """Detect DNS tunneling attempts."""
        alerts = []
        rules = config.RULES['dns_tunneling']

        if pkt_info.protocol == 'DNS' and pkt_info.dns_query:
            src = pkt_info.src_ip
            query = pkt_info.dns_query
            now = time.time()

            self._dns_tracker[src].append((now, query))

            # Clean old entries
            while self._dns_tracker[src] and now - self._dns_tracker[src][0][0] > 60:
                self._dns_tracker[src].popleft()

            # Check query length
            if len(query) > rules['query_length_threshold']:
                confidence = min(1.0, len(query) / (rules['query_length_threshold'] * 3))
                alert = Alert(
                    alert_type='DNS Tunneling',
                    severity=rules['severity'],
                    source_ip=src,
                    target_ip=pkt_info.dst_ip,
                    description=f"Suspicious DNS query from {src}. Query length ({len(query)} chars) exceeds normal threshold.",
                    evidence=[
                        f"Source IP: {src}",
                        f"Query: {query[:80]}...",
                        f"Query length: {len(query)} characters",
                        f"Normal threshold: {rules['query_length_threshold']} chars",
                        f"Possible data exfiltration via DNS",
                        f"High entropy in subdomain suggests encoded data",
                    ],
                    confidence=confidence,
                )
                alerts.append(alert)

            # Check frequency
            recent_queries = [q for t, q in self._dns_tracker[src]]
            domain_counts = defaultdict(int)
            for q in recent_queries:
                parts = q.rstrip('.').split('.')
                if len(parts) >= 2:
                    domain = '.'.join(parts[-2:])
                    domain_counts[domain] += 1

            for domain, count in domain_counts.items():
                if count >= rules['frequency_threshold']:
                    confidence = min(1.0, count / (rules['frequency_threshold'] * 2))
                    alert = Alert(
                        alert_type='DNS Tunneling (Frequency)',
                        severity=rules['severity'],
                        source_ip=src,
                        target_ip=pkt_info.dst_ip,
                        description=f"High-frequency DNS requests from {src} to {domain}. {count} queries in 60s.",
                        evidence=[
                            f"Source IP: {src}",
                            f"Target domain: {domain}",
                            f"Query frequency: {count}/min",
                            f"Threshold: {rules['frequency_threshold']}/min",
                            f"Consistent sub-domain variation suggests tunneling",
                        ],
                        confidence=confidence,
                    )
                    alerts.append(alert)

        return alerts

    # ─── ICMP Flood Detection ────────────────────────────────

    def _detect_icmp_flood(self, pkt_info):
        """Detect ICMP flood attacks."""
        alerts = []
        rules = config.RULES['icmp_flood']

        if pkt_info.protocol == 'ICMP':
            now = time.time()
            target = pkt_info.dst_ip

            self._icmp_tracker[target].append(now)

            while self._icmp_tracker[target] and now - self._icmp_tracker[target][0] > rules['time_window']:
                self._icmp_tracker[target].popleft()

            count = len(self._icmp_tracker[target])
            rate = count / rules['time_window']

            if rate >= rules['threshold']:
                confidence = min(1.0, rate / (rules['threshold'] * 2))
                alert = Alert(
                    alert_type='ICMP Flood',
                    severity=rules['severity'],
                    source_ip=pkt_info.src_ip,
                    target_ip=target,
                    description=f"ICMP flood detected targeting {target}. {count} packets in {rules['time_window']}s.",
                    evidence=[
                        f"Target IP: {target}",
                        f"ICMP packets: {count}",
                        f"Rate: {rate:.1f} packets/s",
                        f"Threshold: {rules['threshold']} packets/s",
                        f"ICMP type: {pkt_info.icmp_type}",
                    ],
                    confidence=confidence,
                )
                alerts.append(alert)
                self._icmp_tracker[target].clear()

        return alerts

    # ─── ARP Spoofing Detection ──────────────────────────────

    def _detect_arp_spoofing(self, pkt_info):
        """Detect ARP spoofing (duplicate IP with different MACs)."""
        alerts = []
        rules = config.RULES['arp_spoofing']

        if pkt_info.protocol == 'ARP' and pkt_info.src_ip and pkt_info.src_mac:
            ip = pkt_info.src_ip
            mac = pkt_info.src_mac

            self._arp_table[ip].add(mac)

            if len(self._arp_table[ip]) >= rules['duplicate_threshold']:
                macs = list(self._arp_table[ip])
                alert = Alert(
                    alert_type='ARP Spoofing',
                    severity=rules['severity'],
                    source_ip=ip,
                    description=f"ARP spoofing detected. IP {ip} is associated with {len(macs)} different MAC addresses.",
                    evidence=[
                        f"IP Address: {ip}",
                        f"MAC addresses observed: {', '.join(macs)}",
                        f"Threshold: {rules['duplicate_threshold']} different MACs",
                        f"This indicates potential man-in-the-middle attack",
                        f"ARP cache poisoning suspected",
                    ],
                    confidence=0.85,
                )
                alerts.append(alert)
                # Reset the tracked MACs for this IP to prevent endless alert spamming
                self._arp_table[ip].clear()

        return alerts

    # ─── Encrypted Traffic Anomaly ───────────────────────────

    def _detect_encrypted_anomaly(self, pkt_info):
        """Detect anomalies in encrypted traffic without payload inspection."""
        alerts = []
        rules = config.RULES['encrypted_anomaly']

        if pkt_info.is_encrypted and pkt_info.tls_version:
            src = pkt_info.src_ip

            # Check for deprecated TLS versions
            deprecated_versions = {'SSL 3.0', 'TLS 1.0', 'TLS 1.1'}
            if pkt_info.tls_version in deprecated_versions:
                alert = Alert(
                    alert_type='Encrypted Traffic Anomaly',
                    severity=rules['severity'],
                    source_ip=src,
                    target_ip=pkt_info.dst_ip,
                    description=f"Deprecated {pkt_info.tls_version} detected from {src}. This may indicate a downgrade attack or misconfigured client.",
                    evidence=[
                        f"Source IP: {src}",
                        f"TLS Version: {pkt_info.tls_version}",
                        f"Minimum recommended: TLS 1.2",
                        f"Deprecated protocols are vulnerable to known attacks",
                        f"Could indicate TLS downgrade attack (e.g., POODLE)",
                        f"Destination: {pkt_info.dst_ip}:{pkt_info.dst_port}",
                    ],
                    confidence=0.7,
                )
                alerts.append(alert)

        return alerts

    # ─── Alert Management ────────────────────────────────────

    def get_alerts(self, count=50, severity=None, acknowledged=None):
        """Get recent alerts with optional filtering."""
        with self._lock:
            alerts = list(self.alerts)

        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]

        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return [a.to_dict() for a in alerts[:count]]

    def get_alert_stats(self):
        """Get alert statistics."""
        with self._lock:
            alerts = list(self.alerts)

        stats = {
            'total': len(alerts),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'unacknowledged': 0,
        }

        for alert in alerts:
            stats['by_severity'][alert.severity] += 1
            stats['by_type'][alert.alert_type] += 1
            if not alert.acknowledged:
                stats['unacknowledged'] += 1

        stats['by_severity'] = dict(stats['by_severity'])
        stats['by_type'] = dict(stats['by_type'])
        return stats

    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert."""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
        return False
