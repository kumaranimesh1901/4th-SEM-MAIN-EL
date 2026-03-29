"""
Flow Analyzer - Tracks network flows and computes flow-level features.
A flow is defined as a bidirectional communication between two endpoints.
"""

import time
import threading
from collections import defaultdict, deque

import config


class Flow:
    """Represents a network flow between two endpoints."""

    __slots__ = [
        'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'start_time', 'last_seen', 'packet_count', 'total_bytes',
        'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
        'flags', 'avg_packet_size', 'min_packet_size', 'max_packet_size',
        'has_syn', 'has_fin', 'has_rst', 'syn_count', 'fin_count',
        'rst_count', 'ack_count', 'psh_count', 'urg_count',
        'encrypted', 'tls_versions', 'inter_arrival_times',
        'payload_sizes', 'dns_queries', 'unique_dst_ports',
    ]

    def __init__(self, flow_id, src_ip, dst_ip, src_port, dst_port, protocol):
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.packet_count = 0
        self.total_bytes = 0
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.flags = set()
        self.avg_packet_size = 0
        self.min_packet_size = float('inf')
        self.max_packet_size = 0
        self.has_syn = False
        self.has_fin = False
        self.has_rst = False
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.ack_count = 0
        self.psh_count = 0
        self.urg_count = 0
        self.encrypted = False
        self.tls_versions = set()
        self.inter_arrival_times = deque(maxlen=100)
        self.payload_sizes = deque(maxlen=100)
        self.dns_queries = []
        self.unique_dst_ports = set()

    @property
    def duration(self):
        return self.last_seen - self.start_time

    @property
    def packets_per_second(self):
        d = self.duration
        return self.packet_count / d if d > 0 else self.packet_count

    @property
    def bytes_per_second(self):
        d = self.duration
        return self.total_bytes / d if d > 0 else self.total_bytes

    def to_feature_dict(self):
        """Convert flow to a feature dictionary for ML model."""
        iat = list(self.inter_arrival_times)
        avg_iat = sum(iat) / len(iat) if iat else 0
        std_iat = (sum((x - avg_iat) ** 2 for x in iat) / len(iat)) ** 0.5 if len(iat) > 1 else 0

        ps = list(self.payload_sizes)
        avg_ps = sum(ps) / len(ps) if ps else 0
        std_ps = (sum((x - avg_ps) ** 2 for x in ps) / len(ps)) ** 0.5 if len(ps) > 1 else 0

        return {
            'duration': self.duration,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'fwd_packets': self.fwd_packets,
            'bwd_packets': self.bwd_packets,
            'fwd_bytes': self.fwd_bytes,
            'bwd_bytes': self.bwd_bytes,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second,
            'avg_packet_size': self.avg_packet_size,
            'min_packet_size': self.min_packet_size if self.min_packet_size != float('inf') else 0,
            'max_packet_size': self.max_packet_size,
            'syn_count': self.syn_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'ack_count': self.ack_count,
            'psh_count': self.psh_count,
            'urg_count': self.urg_count,
            'fwd_bwd_ratio': self.fwd_packets / max(self.bwd_packets, 1),
            'byte_ratio': self.fwd_bytes / max(self.bwd_bytes, 1),
            'avg_inter_arrival': avg_iat,
            'std_inter_arrival': std_iat,
            'avg_payload_size': avg_ps,
            'std_payload_size': std_ps,
            'is_encrypted': int(self.encrypted),
            'unique_dst_ports': len(self.unique_dst_ports),
            'dns_query_count': len(self.dns_queries),
        }


class FlowAnalyzer:
    """
    Tracks and analyzes network flows.
    Groups packets into flows and computes flow-level statistics.
    """

    def __init__(self):
        self.active_flows = {}
        self.completed_flows = deque(maxlen=500)
        self._lock = threading.Lock()
        self._cleanup_interval = 30  # seconds

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name='FlowCleanupThread'
        )
        self._cleanup_thread.start()

    def process_packet(self, pkt_info):
        """Process a packet and update the corresponding flow."""
        if not pkt_info.src_ip or not pkt_info.dst_ip:
            return None

        flow_id = self._compute_flow_id(
            pkt_info.src_ip, pkt_info.dst_ip,
            pkt_info.src_port, pkt_info.dst_port,
            pkt_info.protocol
        )

        with self._lock:
            if flow_id not in self.active_flows:
                flow = Flow(
                    flow_id, pkt_info.src_ip, pkt_info.dst_ip,
                    pkt_info.src_port, pkt_info.dst_port, pkt_info.protocol
                )
                self.active_flows[flow_id] = flow
            else:
                flow = self.active_flows[flow_id]

            # Update flow stats
            now = time.time()
            if flow.packet_count > 0:
                iat = now - flow.last_seen
                flow.inter_arrival_times.append(iat)

            flow.last_seen = now
            flow.packet_count += 1
            flow.total_bytes += pkt_info.length
            flow.payload_sizes.append(pkt_info.payload_size)

            # Forward / backward
            if pkt_info.src_ip == flow.src_ip:
                flow.fwd_packets += 1
                flow.fwd_bytes += pkt_info.length
            else:
                flow.bwd_packets += 1
                flow.bwd_bytes += pkt_info.length

            # Packet size stats
            flow.avg_packet_size = flow.total_bytes / flow.packet_count
            flow.min_packet_size = min(flow.min_packet_size, pkt_info.length)
            flow.max_packet_size = max(flow.max_packet_size, pkt_info.length)

            # Flags
            if pkt_info.flags:
                flow.flags.add(pkt_info.flags)
                if 'S' in pkt_info.flags and 'A' not in pkt_info.flags:
                    flow.has_syn = True
                    flow.syn_count += 1
                if 'F' in pkt_info.flags:
                    flow.has_fin = True
                    flow.fin_count += 1
                if 'R' in pkt_info.flags:
                    flow.has_rst = True
                    flow.rst_count += 1
                if 'A' in pkt_info.flags:
                    flow.ack_count += 1
                if 'P' in pkt_info.flags:
                    flow.psh_count += 1
                if 'U' in pkt_info.flags:
                    flow.urg_count += 1

            # Encrypted traffic
            if pkt_info.is_encrypted:
                flow.encrypted = True
                if pkt_info.tls_version:
                    flow.tls_versions.add(pkt_info.tls_version)

            # DNS queries
            if pkt_info.dns_query:
                flow.dns_queries.append(pkt_info.dns_query)

            # Track unique destination ports
            if pkt_info.dst_port:
                flow.unique_dst_ports.add(pkt_info.dst_port)

        return flow

    def _compute_flow_id(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Compute a bidirectional flow ID."""
        # Sort endpoints so flow is bidirectional
        endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return f"{endpoints[0][0]}:{endpoints[0][1]}-{endpoints[1][0]}:{endpoints[1][1]}-{protocol}"

    def _cleanup_loop(self):
        """Periodically clean up expired flows."""
        while True:
            time.sleep(self._cleanup_interval)
            self._cleanup_expired_flows()

    def _cleanup_expired_flows(self):
        """Move expired flows to completed flows."""
        now = time.time()
        expired = []

        with self._lock:
            for flow_id, flow in self.active_flows.items():
                if now - flow.last_seen > config.FLOW_TIMEOUT:
                    expired.append(flow_id)

            for flow_id in expired:
                flow = self.active_flows.pop(flow_id)
                self.completed_flows.append(flow)

    def get_active_flows_summary(self):
        """Return summary of active flows."""
        with self._lock:
            flows = []
            for flow in self.active_flows.values():
                flows.append({
                    'flow_id': flow.flow_id,
                    'src': f"{flow.src_ip}:{flow.src_port}",
                    'dst': f"{flow.dst_ip}:{flow.dst_port}",
                    'protocol': flow.protocol,
                    'packets': flow.packet_count,
                    'bytes': flow.total_bytes,
                    'duration': round(flow.duration, 2),
                    'pps': round(flow.packets_per_second, 2),
                    'encrypted': flow.encrypted,
                })
            return sorted(flows, key=lambda x: x['packets'], reverse=True)[:50]

    def get_flow_features(self, flow_id=None):
        """Get feature dictionaries for flows (for ML model)."""
        with self._lock:
            if flow_id:
                flow = self.active_flows.get(flow_id)
                return flow.to_feature_dict() if flow else None
            return [f.to_feature_dict() for f in self.active_flows.values()]
