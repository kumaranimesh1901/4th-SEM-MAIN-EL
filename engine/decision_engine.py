"""
Decision Engine for Smart Firewall & IDS.
Combines outputs from rule-based detection, Isolation Forest anomaly detection,
and XGBoost classification to make final BLOCK / FLAG / ALLOW decisions.

Decision Logic:
  - If Rule-Based + ML both confirm attack → BLOCK traffic (auto)
  - If only one engine detects, or anomaly only  → FLAG as suspicious (manual action)
  - If neither detects → ALLOW traffic
  - If an IP is flagged >= threshold times → auto-BLOCK
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime


class FirewallAction:
    """Represents a firewall decision for a packet/flow."""

    BLOCK = 'BLOCK'
    FLAG = 'FLAG'
    ALLOW = 'ALLOW'

    def __init__(self, action, reason='', source_ip='', target_ip='',
                 attack_type='', severity='low', confidence=0.0,
                 rule_matched=False, ml_matched=False, anomaly_detected=False):
        self.action = action
        self.reason = reason
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.attack_type = attack_type
        self.severity = severity
        self.confidence = confidence
        self.rule_matched = rule_matched
        self.ml_matched = ml_matched
        self.anomaly_detected = anomaly_detected
        self.timestamp = time.time()

    def to_dict(self):
        return {
            'action': self.action,
            'reason': self.reason,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'confidence': round(self.confidence, 3),
            'rule_matched': self.rule_matched,
            'ml_matched': self.ml_matched,
            'anomaly_detected': self.anomaly_detected,
            'timestamp': self.timestamp,
            'time_str': datetime.fromtimestamp(self.timestamp).strftime('%H:%M:%S'),
        }


class DecisionEngine:
    """
    Central decision engine that combines detection outputs to produce
    firewall actions: BLOCK, FLAG, or ALLOW.

    Implements the hybrid decision logic:
      1. Rule-based + ML both confirm → BLOCK (auto-firewall)
      2. Single engine detection → FLAG (manual action required)
      3. Repeated FLAGs → auto-BLOCK after threshold
      4. Neither engine flags → ALLOW
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Track recent decisions
        self._recent_decisions = deque(maxlen=1000)

        # Blocked IP tracking (simulated firewall)
        self._blocked_ips = {}        # ip -> {timestamp, reason, duration}
        self._flagged_ips = {}        # ip -> {timestamp, reason, count}

        # Statistics
        self.stats = {
            'total_decisions': 0,
            'blocked': 0,
            'flagged': 0,
            'allowed': 0,
            'blocked_ips_count': 0,
            'flagged_ips_count': 0,
        }

        # Decision callbacks (for dashboard/alerting)
        self._callbacks = []

        # Configuration
        self.block_duration = 300     # seconds to block an IP (5 minutes)
        self.flag_threshold = 3       # number of flagged events before auto-block
        self.min_confidence = 0.5     # minimum confidence for ML-based decisions

    def register_callback(self, callback):
        """Register callback for firewall decisions."""
        self._callbacks.append(callback)

    def make_decision(self, source_ip, target_ip='', rule_alerts=None,
                      ml_result=None, anomaly_result=None):
        """
        Make a firewall decision based on combined detection outputs.

        Args:
            source_ip: The source IP of the traffic
            target_ip: The destination IP (optional)
            rule_alerts: list of Alert objects from rule-based detection
            ml_result: dict with keys 'is_attack', 'attack_type', 'confidence'
                       from XGBoost classification
            anomaly_result: dict with keys 'is_anomaly', 'confidence'
                           from Isolation Forest

        Returns:
            FirewallAction: The decision (BLOCK, FLAG, or ALLOW)
        """
        # Check if IP is already blocked
        if self._is_ip_blocked(source_ip):
            action = FirewallAction(
                action=FirewallAction.BLOCK,
                reason='IP is currently blocked',
                source_ip=source_ip,
                target_ip=target_ip,
                severity='high',
                confidence=1.0,
                rule_matched=True,
            )
            self._record_decision(action)
            return action

        rule_matched = bool(rule_alerts and len(rule_alerts) > 0)
        ml_matched = bool(ml_result and ml_result.get('is_attack', False)
                          and ml_result.get('confidence', 0) >= self.min_confidence)
        anomaly_detected = bool(anomaly_result and anomaly_result.get('is_anomaly', False)
                                and anomaly_result.get('confidence', 0) >= self.min_confidence)

        # Determine attack type and severity
        attack_type = ''
        severity = 'low'
        confidence = 0.0

        if rule_matched:
            # Use the highest severity rule alert
            best_alert = max(rule_alerts, key=lambda a: self._severity_rank(a.severity))
            attack_type = best_alert.alert_type
            severity = best_alert.severity
            confidence = best_alert.confidence

        if ml_matched:
            ml_type = ml_result.get('attack_type', 'Unknown')
            ml_conf = ml_result.get('confidence', 0)
            if ml_conf > confidence:
                attack_type = ml_type
                confidence = ml_conf
            severity = self._get_highest_severity(
                severity,
                self._ml_severity(ml_type, ml_conf)
            )

        # ─── Decision Logic ───────────────────────────────────

        # Case 1: Both rule-based AND ML confirm attack → BLOCK
        if rule_matched and ml_matched:
            action = FirewallAction(
                action=FirewallAction.BLOCK,
                reason=f'Hybrid confirmed (Rule + ML): {attack_type}',
                source_ip=source_ip,
                target_ip=target_ip,
                attack_type=attack_type,
                severity=severity,
                confidence=min(1.0, confidence + 0.15),
                rule_matched=True,
                ml_matched=True,
                anomaly_detected=anomaly_detected,
            )
            self._block_ip(source_ip, action.reason)
            self._record_decision(action)
            return action

        # Case 2: Rule-based with critical severity + high confidence → BLOCK
        if rule_matched and severity == 'critical' and confidence >= 0.85:
            action = FirewallAction(
                action=FirewallAction.BLOCK,
                reason=f'Critical rule detection: {attack_type}',
                source_ip=source_ip,
                target_ip=target_ip,
                attack_type=attack_type,
                severity=severity,
                confidence=confidence,
                rule_matched=True,
                ml_matched=False,
                anomaly_detected=anomaly_detected,
            )
            self._block_ip(source_ip, action.reason)
            self._record_decision(action)
            return action

        # Case 3: ML highly confident + anomaly → FLAG (action required)
        if ml_matched and anomaly_detected and confidence >= 0.7:
            action = FirewallAction(
                action=FirewallAction.FLAG,
                reason=f'ML + Anomaly confirmed: {attack_type} — Action Required',
                source_ip=source_ip,
                target_ip=target_ip,
                attack_type=attack_type,
                severity=severity,
                confidence=confidence,
                rule_matched=False,
                ml_matched=True,
                anomaly_detected=True,
            )
            self._flag_ip(source_ip, action.reason)
            self._record_decision(action)
            return action

        # Case 4: Rule-based detection only → FLAG
        if rule_matched and confidence >= 0.5:
            action = FirewallAction(
                action=FirewallAction.FLAG,
                reason=f'Rule-based detection: {attack_type} — Action Required',
                source_ip=source_ip,
                target_ip=target_ip,
                attack_type=attack_type,
                severity=severity if severity != 'low' else 'medium',
                confidence=confidence,
                rule_matched=True,
                ml_matched=False,
                anomaly_detected=anomaly_detected,
            )
            self._flag_ip(source_ip, action.reason)
            self._record_decision(action)
            return action

        # Case 5: ML detection only → FLAG
        if ml_matched:
            action = FirewallAction(
                action=FirewallAction.FLAG,
                reason=f'ML classification: {attack_type} — Action Required',
                source_ip=source_ip,
                target_ip=target_ip,
                attack_type=attack_type,
                severity=severity if severity != 'low' else 'medium',
                confidence=confidence,
                rule_matched=False,
                ml_matched=True,
                anomaly_detected=anomaly_detected,
            )
            self._flag_ip(source_ip, action.reason)
            self._record_decision(action)
            return action

        # Case 6: Anomaly only → FLAG (lower priority)
        if anomaly_detected:
            action = FirewallAction(
                action=FirewallAction.FLAG,
                reason='Anomaly detected — Action Required',
                source_ip=source_ip,
                target_ip=target_ip,
                attack_type='Anomaly',
                severity='medium',
                confidence=anomaly_result.get('confidence', 0.5),
                rule_matched=False,
                ml_matched=False,
                anomaly_detected=True,
            )
            self._flag_ip(source_ip, action.reason)
            self._record_decision(action)
            return action

        # Case 7: Nothing detected → ALLOW
        action = FirewallAction(
            action=FirewallAction.ALLOW,
            reason='No threats detected',
            source_ip=source_ip,
            target_ip=target_ip,
            severity='low',
            confidence=0.0,
        )
        self._record_decision(action)
        return action

    def _block_ip(self, ip, reason):
        """Add IP to blocked list (simulated firewall)."""
        with self._lock:
            self._blocked_ips[ip] = {
                'timestamp': time.time(),
                'reason': reason,
                'duration': self.block_duration,
            }
            # Remove from flagged if present
            if ip in self._flagged_ips:
                del self._flagged_ips[ip]
            self.stats['blocked_ips_count'] = len(self._blocked_ips)
            self.stats['flagged_ips_count'] = len(self._flagged_ips)

    def _flag_ip(self, ip, reason):
        """Add IP to flagged list, auto-block after threshold."""
        with self._lock:
            if ip not in self._flagged_ips:
                self._flagged_ips[ip] = {
                    'timestamp': time.time(),
                    'reason': reason,
                    'count': 1,
                }
            else:
                self._flagged_ips[ip]['count'] += 1
                self._flagged_ips[ip]['timestamp'] = time.time()
                self._flagged_ips[ip]['reason'] = reason

            self.stats['flagged_ips_count'] = len(self._flagged_ips)

            # Auto-block after repeated flags
            if self._flagged_ips[ip]['count'] >= self.flag_threshold:
                print(f"[!] Auto-blocking {ip} after {self._flagged_ips[ip]['count']} flags")
                self._blocked_ips[ip] = {
                    'timestamp': time.time(),
                    'reason': f"Auto-blocked: {reason} (flagged {self._flagged_ips[ip]['count']} times)",
                    'duration': self.block_duration,
                }
                del self._flagged_ips[ip]
                self.stats['blocked_ips_count'] = len(self._blocked_ips)
                self.stats['flagged_ips_count'] = len(self._flagged_ips)

    def _is_ip_blocked(self, ip):
        """Check if an IP is currently blocked."""
        with self._lock:
            if ip in self._blocked_ips:
                entry = self._blocked_ips[ip]
                elapsed = time.time() - entry['timestamp']
                if elapsed < entry['duration']:
                    return True
                else:
                    # Block expired, remove it
                    del self._blocked_ips[ip]
                    self.stats['blocked_ips_count'] = len(self._blocked_ips)
            return False

    def _record_decision(self, action):
        """Record a decision and update stats."""
        with self._lock:
            self._recent_decisions.append(action)

            self.stats['total_decisions'] += 1
            if action.action == FirewallAction.BLOCK:
                self.stats['blocked'] += 1
            elif action.action == FirewallAction.FLAG:
                self.stats['flagged'] += 1
            else:
                self.stats['allowed'] += 1

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(action)
            except Exception as e:
                print(f"[!] Decision callback error: {e}")

    def _severity_rank(self, severity):
        """Convert severity string to numeric rank for comparison."""
        ranks = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return ranks.get(severity, 0)

    def _get_highest_severity(self, s1, s2):
        """Return the more severe of two severity levels."""
        return s1 if self._severity_rank(s1) >= self._severity_rank(s2) else s2

    def _ml_severity(self, attack_type, confidence):
        """Determine severity from ML classification output."""
        critical_types = {'DDoS', 'Ransomware', 'APT'}
        high_types = {'SQL Injection', 'Brute Force', 'Bot', 'Infiltration'}

        if attack_type in critical_types and confidence > 0.7:
            return 'critical'
        elif attack_type in critical_types or attack_type in high_types:
            return 'high'
        elif confidence > 0.6:
            return 'medium'
        return 'low'

    # ─── Firewall Management ─────────────────────────────────

    def block_ip(self, ip, reason):
        """Manually block an IP address."""
        with self._lock:
            # If flagged, remove from flags
            if ip in self._flagged_ips:
                del self._flagged_ips[ip]

            self._blocked_ips[ip] = {
                'timestamp': time.time(),
                'reason': reason,
                'duration': self.block_duration,
            }
            self.stats['blocked_ips_count'] = len(self._blocked_ips)
            self.stats['flagged_ips_count'] = len(self._flagged_ips)
            return True

    def unblock_ip(self, ip):
        """Manually unblock an IP address."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self.stats['blocked_ips_count'] = len(self._blocked_ips)
                return True
        return False

    def get_blocked_ips(self):
        """Get list of currently blocked IPs."""
        with self._lock:
            now = time.time()
            result = []
            expired = []
            for ip, entry in self._blocked_ips.items():
                elapsed = now - entry['timestamp']
                if elapsed < entry['duration']:
                    result.append({
                        'ip': ip,
                        'reason': entry['reason'],
                        'blocked_at': datetime.fromtimestamp(
                            entry['timestamp']
                        ).strftime('%H:%M:%S'),
                        'remaining': int(entry['duration'] - elapsed),
                    })
                else:
                    expired.append(ip)

            for ip in expired:
                del self._blocked_ips[ip]
            self.stats['blocked_ips_count'] = len(self._blocked_ips)
            return result

    def get_flagged_ips(self):
        """Get list of currently flagged IPs."""
        with self._lock:
            return [{
                'ip': ip,
                'reason': entry['reason'],
                'count': entry['count'],
                'first_seen': datetime.fromtimestamp(
                    entry['timestamp']
                ).strftime('%H:%M:%S'),
            } for ip, entry in self._flagged_ips.items()]

    def get_recent_decisions(self, count=50):
        """Get recent firewall decisions."""
        with self._lock:
            decisions = list(self._recent_decisions)
        decisions.sort(key=lambda d: d.timestamp, reverse=True)
        return [d.to_dict() for d in decisions[:count]]

    def get_stats(self):
        """Get decision engine statistics."""
        return dict(self.stats)

    def cleanup_expired(self):
        """Clean up expired blocks and old flags."""
        now = time.time()
        with self._lock:
            # Remove expired blocks
            expired_blocks = [
                ip for ip, entry in self._blocked_ips.items()
                if now - entry['timestamp'] >= entry['duration']
            ]
            for ip in expired_blocks:
                del self._blocked_ips[ip]

            # Remove old flags (> 10 minutes old)
            expired_flags = [
                ip for ip, entry in self._flagged_ips.items()
                if now - entry['timestamp'] > 600
            ]
            for ip in expired_flags:
                del self._flagged_ips[ip]

            self.stats['blocked_ips_count'] = len(self._blocked_ips)
            self.stats['flagged_ips_count'] = len(self._flagged_ips)
