"""
Hybrid Detection Manager.
Combines rule-based and ML detection for comprehensive threat analysis.
Integrates the Decision Engine for BLOCK/FLAG/ALLOW actions.
Sends Telegram alerts for high-severity detections.

Architecture:
  PacketCapture → HybridDetector
                    ├─ RuleBasedDetector (pattern matching)
                    ├─ MLDetector (XGBoost + Isolation Forest)
                    ├─ DecisionEngine (BLOCK / FLAG / ALLOW)
                    └─ TelegramAlerter (notifications)
"""

import time
import threading
from collections import deque, defaultdict

from detection.rule_engine import RuleBasedDetector, Alert
from detection.ml_detector import MLDetector
from engine.flow_analyzer import FlowAnalyzer
from engine.decision_engine import DecisionEngine
from engine.feature_extraction import FeatureExtractor
from alerts.telegram_alert import TelegramAlerter

import config


class HybridDetector:
    """
    Combines rule-based and ML-based detection with a decision engine.
    Produces BLOCK/FLAG/ALLOW decisions and sends alert notifications.
    """

    def __init__(self):
        # Detection engines
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLDetector()
        self.flow_analyzer = FlowAnalyzer()
        self.feature_extractor = FeatureExtractor()

        # Decision engine (firewall)
        self.decision_engine = DecisionEngine()
        self.decision_engine.block_duration = config.FIREWALL.get('block_duration', 300)
        self.decision_engine.flag_threshold = config.FIREWALL.get('flag_threshold', 3)
        self.decision_engine.min_confidence = config.FIREWALL.get('min_ml_confidence', 0.5)

        # Telegram alerter
        self.telegram = TelegramAlerter(
            bot_token=config.TELEGRAM_BOT_TOKEN,
            chat_id=config.TELEGRAM_CHAT_ID,
        )

        # Alert management
        self._alert_callbacks = []
        self._decision_callbacks = []
        self._all_alerts = deque(maxlen=500)
        self._lock = threading.Lock()

        # ── ML result cache per source IP ──────────────────────
        # Stores the most recent ML prediction for each source IP so that
        # when a rule-based alert fires on a DIFFERENT packet from the same
        # IP, the decision engine still receives both rule AND ML context.
        self._ml_cache = {}           # ip -> {result, timestamp}
        self._ml_cache_ttl = 120      # seconds before a cached result expires

        # Cross-register alert callbacks
        self.rule_detector.register_alert_callback(self._on_rule_alert)
        self.ml_detector.register_alert_callback(self._on_ml_alert)

        # Normal traffic tracking
        self._normal_traffic = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocol_counts': defaultdict(int),
            'recent_safe_flows': deque(maxlen=50),
            'safe_ips': defaultdict(lambda: {'packets': 0, 'bytes': 0, 'last_seen': 0}),
        }

        # Statistics
        self.stats = {
            'rule_alerts': 0,
            'ml_alerts': 0,
            'correlated_alerts': 0,
            'blocked': 0,
            'flagged': 0,
            'allowed': 0,
        }

        # Start periodic cleanup
        self._cleanup_thread = threading.Thread(
            target=self._periodic_cleanup,
            daemon=True,
            name='HybridCleanup',
        )
        self._cleanup_thread.start()

    def register_alert_callback(self, callback):
        """Register callback for all alerts."""
        self._alert_callbacks.append(callback)

    def register_decision_callback(self, callback):
        """Register callback for firewall decisions."""
        self._decision_callbacks.append(callback)
        self.decision_engine.register_callback(callback)

    # ─── Core Pipeline ────────────────────────────────────────

    def process_packet(self, pkt_info):
        """
        Process a packet through the full detection pipeline.

        Flow:
        1. Extract features
        2. Update flow
        3. Rule-based detection
        4. ML detection (run on every qualifying flow packet, cache results)
        5. Decision engine — combine rule + cached ML for same src IP
        6. Telegram alerts for high severity
        7. Track normal traffic
        """
        # Step 1: Extract packet features
        pkt_features = self.feature_extractor.extract_packet_features(pkt_info)

        # Step 2: Update flow
        flow = self.flow_analyzer.process_packet(pkt_info)

        # Step 3: Rule-based detection
        rule_alerts = self.rule_detector.analyze_packet(pkt_info, flow)

        # Step 4: ML detection
        # Run ML on every 3rd packet of flows with >= 3 packets
        ml_result = None
        anomaly_result = None
        ml_ran_this_packet = False

        if flow and flow.packet_count >= 3 and flow.packet_count % 3 == 0:
            ml_result, anomaly_result = self._run_ml_prediction(flow, pkt_info)
            ml_ran_this_packet = True

        # Step 4b: If rules fired but ML didn't run yet, FORCE ML on this flow
        # This is the key to getting hybrid (Rule + ML) decisions together
        if rule_alerts and not ml_ran_this_packet and flow:
            ml_result, anomaly_result = self._run_ml_prediction(flow, pkt_info)
            ml_ran_this_packet = True

        # Step 4c: If ML still didn't run (no flow / too few packets),
        # use cached ML result for this source IP
        if ml_result is None and anomaly_result is None:
            cached = self._ml_cache.get(pkt_info.src_ip)
            if cached and (time.time() - cached['timestamp']) < self._ml_cache_ttl:
                if cached.get('is_anomaly_result'):
                    anomaly_result = cached['result']
                else:
                    ml_result = cached['result']

        # Step 5: Decision Engine — run when rules or ML detected something
        # Always pass ml_result to the decision engine when rules fire,
        # so the firewall decision table can show ML was at least consulted
        if rule_alerts or (ml_result and ml_result.get('is_attack')) or anomaly_result:
            decision = self.decision_engine.make_decision(
                source_ip=pkt_info.src_ip,
                target_ip=pkt_info.dst_ip,
                rule_alerts=rule_alerts,
                ml_result=ml_result if ml_result else None,
                anomaly_result=anomaly_result,
            )

            # Update stats
            if decision.action == 'BLOCK':
                self.stats['blocked'] += 1
                # Send Telegram alert for blocks
                self.telegram.send_firewall_action(decision)
            elif decision.action == 'FLAG':
                self.stats['flagged'] += 1
                # Send Telegram for high/critical severity flags
                if decision.severity in ('high', 'critical'):
                    self.telegram.send_firewall_action(decision)
            else:
                self.stats['allowed'] += 1
        else:
            # Step 7: Track normal/clean traffic
            self._track_normal_traffic(pkt_info)

    def _run_ml_prediction(self, flow, pkt_info):
        """
        Run ML prediction on a flow and cache the result.
        Returns (ml_result, anomaly_result) tuple.
        """
        ml_result = None
        anomaly_result = None

        features = flow.to_feature_dict()
        features['src_ip'] = pkt_info.src_ip
        features['dst_ip'] = pkt_info.dst_ip

        # Add to training data
        self.ml_detector.add_training_sample(features)

        # Predict
        if self.ml_detector.is_trained or self.ml_detector.xgb_loaded or flow.packet_count >= 6:
            if self.ml_detector.xgb_loaded:
                is_attack, attack_type, confidence, explanations = \
                    self.ml_detector.predict_xgboost(features)
                ml_result = {
                    'is_attack': is_attack,
                    'attack_type': attack_type,
                    'confidence': confidence,
                    'explanations': explanations,
                }
            else:
                is_anomaly, confidence, explanations = \
                    self.ml_detector.predict(features)
                anomaly_result = {
                    'is_anomaly': is_anomaly,
                    'confidence': confidence,
                    'explanations': explanations,
                }

        # Cache ML result for this source IP
        if ml_result is not None:
            self._ml_cache[pkt_info.src_ip] = {
                'result': ml_result,
                'timestamp': time.time(),
            }
        elif anomaly_result is not None:
            self._ml_cache[pkt_info.src_ip] = {
                'result': anomaly_result,
                'timestamp': time.time(),
                'is_anomaly_result': True,
            }

        return ml_result, anomaly_result

    def _track_normal_traffic(self, pkt_info):
        """Track packets that passed through with no detection."""
        self._normal_traffic['total_packets'] += 1
        self._normal_traffic['total_bytes'] += pkt_info.length
        self._normal_traffic['protocol_counts'][pkt_info.protocol] += 1

        if pkt_info.src_ip:
            ip_data = self._normal_traffic['safe_ips'][pkt_info.src_ip]
            ip_data['packets'] += 1
            ip_data['bytes'] += pkt_info.length
            ip_data['last_seen'] = time.time()

    def _on_rule_alert(self, alert):
        """Handle rule-based alert — add to store and notify UI immediately."""
        self.stats['rule_alerts'] += 1
        with self._lock:
            self._all_alerts.append(alert)
        # Notify UI so the alert appears on the dashboard right away
        self._notify_callbacks(alert)

    def _on_ml_alert(self, alert):
        """
        Handle ML-based alert.
        Check if it corroborates a recent rule-based alert from the same IP.
        If so, upgrade to 'hybrid' detection and boost confidence.
        Otherwise, show the standalone ML alert.
        """
        self.stats['ml_alerts'] += 1
        is_corroborated = False

        with self._lock:
            for existing_alert in self._all_alerts:
                # Match against rule-based alerts from same source IP within 60s
                if (existing_alert.source_ip == alert.source_ip
                        and abs(existing_alert.timestamp - alert.timestamp) < 60
                        and existing_alert.detection_method in ('rule-based', 'machine-learning', 'machine-learning-xgboost')):
                    # Upgrade existing alert → hybrid
                    existing_alert.confidence = min(1.0, existing_alert.confidence + 0.15)
                    existing_alert.evidence.append(
                        f"⚡ Corroborated by ML: {alert.alert_type} ({alert.confidence:.0%})"
                    )
                    existing_alert.detection_method = 'hybrid'
                    self.stats['correlated_alerts'] += 1
                    is_corroborated = True

                    # Notify UI to update the existing alert
                    self._notify_callbacks(existing_alert)

                    # Send telegram notification for the hybrid detection
                    self.telegram.send_alert(existing_alert)
                    break

            if not is_corroborated:
                # Standalone ML alert — still show it on the dashboard
                alert.detection_method = getattr(alert, 'detection_method', 'machine-learning')
                self._all_alerts.append(alert)
                # Notify UI for standalone ML alerts too
                self._notify_callbacks(alert)

                # Send telegram if high-confidence standalone ML
                if alert.confidence >= 0.8 and alert.severity in ('high', 'critical'):
                    self.telegram.send_alert(alert)

    def _notify_callbacks(self, alert):
        """Notify all registered callbacks."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"[!] Alert notification error: {e}")

    def _periodic_cleanup(self):
        """Periodically clean up expired data."""
        while True:
            time.sleep(60)
            try:
                self.decision_engine.cleanup_expired()
                self.feature_extractor.cleanup_old_data()
                # Trim old normal traffic IP entries (older than 5 minutes)
                now = time.time()
                stale_ips = [
                    ip for ip, data in self._normal_traffic['safe_ips'].items()
                    if now - data['last_seen'] > 300
                ]
                for ip in stale_ips:
                    del self._normal_traffic['safe_ips'][ip]

                # Clean expired ML cache entries
                stale_ml = [
                    ip for ip, data in self._ml_cache.items()
                    if now - data['timestamp'] > self._ml_cache_ttl
                ]
                for ip in stale_ml:
                    del self._ml_cache[ip]

            except Exception:
                pass

    # ─── API Methods ─────────────────────────────────────────

    def get_all_alerts(self, count=50, severity=None):
        """Get ALL alerts (rule-based, ML, and hybrid)."""
        with self._lock:
            alerts = list(self._all_alerts)

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return [a.to_dict() for a in alerts[:count]]

    def get_normal_traffic_summary(self):
        """Get summary of clean/normal (non-malicious) traffic."""
        safe_ips = self._normal_traffic['safe_ips']

        # Sort top safe IPs by packet count
        top_safe_ips = sorted(
            [
                {
                    'ip': ip,
                    'packets': data['packets'],
                    'bytes': data['bytes'],
                    'last_seen': data['last_seen'],
                }
                for ip, data in safe_ips.items()
            ],
            key=lambda x: x['packets'],
            reverse=True,
        )[:20]

        return {
            'total_clean_packets': self._normal_traffic['total_packets'],
            'total_clean_bytes': self._normal_traffic['total_bytes'],
            'protocol_counts': dict(self._normal_traffic['protocol_counts']),
            'unique_safe_ips': len(safe_ips),
            'top_safe_ips': top_safe_ips,
        }

    def _get_hybrid_stats(self):
        """Get statistics specifically for hybrid alerts."""
        with self._lock:
            hybrid_alerts = [a for a in self._all_alerts if getattr(a, 'detection_method', '') == 'hybrid']
        
        stats = {
            'total': len(hybrid_alerts),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {}
        }
        
        for a in hybrid_alerts:
            sev = a.severity
            if sev in stats['by_severity']:
                stats['by_severity'][sev] += 1
            else:
                stats['by_severity'][sev] = 1
                
            atype = a.alert_type
            stats['by_type'][atype] = stats['by_type'].get(atype, 0) + 1
            
        return stats

    def _get_all_alert_stats(self):
        """Get statistics for ALL alerts (not just hybrid)."""
        with self._lock:
            all_alerts = list(self._all_alerts)

        stats = {
            'total': len(all_alerts),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {},
            'by_method': {'rule-based': 0, 'machine-learning': 0, 'hybrid': 0},
        }

        for a in all_alerts:
            sev = a.severity
            if sev in stats['by_severity']:
                stats['by_severity'][sev] += 1

            atype = a.alert_type
            stats['by_type'][atype] = stats['by_type'].get(atype, 0) + 1

            method = getattr(a, 'detection_method', 'rule-based')
            if 'machine-learning' in method:
                stats['by_method']['machine-learning'] += 1
            elif method == 'hybrid':
                stats['by_method']['hybrid'] += 1
            else:
                stats['by_method']['rule-based'] += 1

        return stats

    def get_stats(self):
        """Get combined detection statistics."""
        return {
            'rule_based': self.rule_detector.get_alert_stats(),
            'ml': self.ml_detector.get_status(),
            'combined': self.stats,
            'hybrid': self._get_hybrid_stats(),
            'all_alerts': self._get_all_alert_stats(),
            'firewall': self.decision_engine.get_stats(),
            'telegram': self.telegram.get_stats(),
            'flows': {
                'active': len(self.flow_analyzer.active_flows),
                'completed': len(self.flow_analyzer.completed_flows),
            },
            'normal_traffic': {
                'total_clean_packets': self._normal_traffic['total_packets'],
                'total_clean_bytes': self._normal_traffic['total_bytes'],
                'unique_safe_ips': len(self._normal_traffic['safe_ips']),
            },
        }

    def get_firewall_status(self):
        """Get firewall status (blocked/flagged IPs)."""
        return {
            'blocked_ips': self.decision_engine.get_blocked_ips(),
            'flagged_ips': self.decision_engine.get_flagged_ips(),
            'recent_decisions': self.decision_engine.get_recent_decisions(20),
            'stats': self.decision_engine.get_stats(),
        }

    def unblock_ip(self, ip):
        """Unblock an IP address."""
        return self.decision_engine.unblock_ip(ip)

    def acknowledge_alert(self, alert_id):
        """Acknowledge an alert."""
        with self._lock:
            for alert in self._all_alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
        return self.rule_detector.acknowledge_alert(alert_id)
