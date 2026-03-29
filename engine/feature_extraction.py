"""
Feature Extraction Module.
Extracts network flow features from captured packets for ML analysis.
Provides structured feature vectors for both training and real-time prediction.

Features extracted:
  - Source IP, Destination IP, Ports, Protocol
  - Packet count, Packet rate, Payload size
  - Flow duration, Inter-arrival times
  - Flag counts (SYN, FIN, RST, ACK, PSH, URG)
  - Encryption indicators, DNS query info
"""

import time
import threading
import numpy as np
from collections import deque, defaultdict


class FeatureExtractor:
    """
    Extracts structured features from raw packet information and network flows.
    Provides feature vectors suitable for ML model input.
    """

    # Standard feature names for the ML pipeline
    FEATURE_NAMES = [
        'duration', 'packet_count', 'total_bytes', 'fwd_packets', 'bwd_packets',
        'fwd_bytes', 'bwd_bytes', 'packets_per_second', 'bytes_per_second',
        'avg_packet_size', 'min_packet_size', 'max_packet_size',
        'syn_count', 'fin_count', 'rst_count', 'ack_count', 'psh_count', 'urg_count',
        'fwd_bwd_ratio', 'byte_ratio', 'avg_inter_arrival', 'std_inter_arrival',
        'avg_payload_size', 'std_payload_size', 'is_encrypted', 'unique_dst_ports',
        'dns_query_count',
    ]

    def __init__(self):
        self._lock = threading.Lock()
        # Track per-IP packet rates for feature enrichment
        self._ip_packet_history = defaultdict(lambda: deque(maxlen=500))
        self._ip_byte_history = defaultdict(lambda: deque(maxlen=500))

    def extract_packet_features(self, pkt_info):
        """
        Extract basic features from a single PacketInfo object.

        Args:
            pkt_info: PacketInfo instance from packet_capture module

        Returns:
            dict: Feature dictionary with packet-level features
        """
        now = time.time()

        # Track packet rate per source IP
        src_ip = pkt_info.src_ip or 'unknown'
        self._ip_packet_history[src_ip].append(now)
        self._ip_byte_history[src_ip].append(pkt_info.length)

        # Calculate packet rate for this source IP (packets in last 60s)
        cutoff = now - 60.0
        recent_times = [t for t in self._ip_packet_history[src_ip] if t > cutoff]
        packet_rate = len(recent_times) / 60.0 if recent_times else 0

        # Calculate byte rate for this source IP
        recent_indices = [i for i, t in enumerate(self._ip_packet_history[src_ip]) if t > cutoff]
        byte_list = list(self._ip_byte_history[src_ip])
        recent_bytes = sum(byte_list[i] for i in recent_indices if i < len(byte_list))
        byte_rate = recent_bytes / 60.0 if recent_indices else 0

        features = {
            'timestamp': pkt_info.timestamp,
            'src_ip': pkt_info.src_ip,
            'dst_ip': pkt_info.dst_ip,
            'src_port': pkt_info.src_port,
            'dst_port': pkt_info.dst_port,
            'protocol': pkt_info.protocol,
            'length': pkt_info.length,
            'payload_size': pkt_info.payload_size,
            'flags': pkt_info.flags,
            'ttl': pkt_info.ttl,
            'is_encrypted': int(pkt_info.is_encrypted),
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'has_syn': 1 if pkt_info.flags and 'S' in pkt_info.flags else 0,
            'has_fin': 1 if pkt_info.flags and 'F' in pkt_info.flags else 0,
            'has_rst': 1 if pkt_info.flags and 'R' in pkt_info.flags else 0,
            'has_ack': 1 if pkt_info.flags and 'A' in pkt_info.flags else 0,
            'has_psh': 1 if pkt_info.flags and 'P' in pkt_info.flags else 0,
            'dns_query': pkt_info.dns_query,
            'window_size': pkt_info.window_size,
        }

        return features

    def extract_flow_features(self, flow):
        """
        Extract ML-ready features from a Flow object.

        Args:
            flow: Flow instance from flow_analyzer module

        Returns:
            dict: Feature dictionary suitable for ML model input
        """
        if flow is None:
            return None

        features = flow.to_feature_dict()

        # Enrich with additional computed features
        features['flow_id'] = flow.flow_id
        features['protocol'] = flow.protocol

        return features

    def flow_features_to_vector(self, flow_features):
        """
        Convert a flow feature dictionary to an ordered numeric vector.

        Args:
            flow_features: dict from extract_flow_features()

        Returns:
            list: Ordered list of float values matching FEATURE_NAMES
        """
        try:
            return [float(flow_features.get(name, 0)) for name in self.FEATURE_NAMES]
        except (ValueError, TypeError):
            return None

    def batch_extract(self, packets):
        """
        Extract features from a batch of packets.

        Args:
            packets: list of PacketInfo instances

        Returns:
            list[dict]: List of feature dictionaries
        """
        return [self.extract_packet_features(pkt) for pkt in packets]

    def get_ip_stats(self, ip_address, time_window=60):
        """
        Get aggregated statistics for a specific IP address.

        Args:
            ip_address: The IP to get stats for
            time_window: lookback window in seconds

        Returns:
            dict: Statistics for the given IP
        """
        now = time.time()
        cutoff = now - time_window

        timestamps = [t for t in self._ip_packet_history[ip_address] if t > cutoff]
        byte_list = list(self._ip_byte_history[ip_address])

        if not timestamps:
            return {
                'packet_count': 0,
                'packet_rate': 0,
                'total_bytes': 0,
                'byte_rate': 0,
            }

        total_bytes = sum(byte_list[-len(timestamps):]) if byte_list else 0

        return {
            'packet_count': len(timestamps),
            'packet_rate': len(timestamps) / time_window,
            'total_bytes': total_bytes,
            'byte_rate': total_bytes / time_window,
        }

    def cleanup_old_data(self, max_age=300):
        """
        Remove tracking data older than max_age seconds.
        Called periodically to prevent memory growth.

        Args:
            max_age: Maximum age in seconds for tracking data
        """
        now = time.time()
        cutoff = now - max_age

        with self._lock:
            empty_ips = []
            for ip in list(self._ip_packet_history.keys()):
                # Remove old entries
                while (self._ip_packet_history[ip] and
                       self._ip_packet_history[ip][0] < cutoff):
                    self._ip_packet_history[ip].popleft()
                    if self._ip_byte_history[ip]:
                        self._ip_byte_history[ip].popleft()

                if not self._ip_packet_history[ip]:
                    empty_ips.append(ip)

            # Remove empty entries
            for ip in empty_ips:
                del self._ip_packet_history[ip]
                if ip in self._ip_byte_history:
                    del self._ip_byte_history[ip]
