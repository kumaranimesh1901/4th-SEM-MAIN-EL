"""
Packet Capture Engine using Scapy.
Captures network packets in real-time and extracts metadata for analysis.
Supports encrypted traffic analysis via metadata (no payload inspection).

On macOS without sudo, falls back to tcpdump-based capture via subprocess
to capture REAL network traffic (not simulated data).
"""

import threading
import time
import hashlib
import subprocess
import struct
from collections import deque, defaultdict
from datetime import datetime

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, ARP, Ether, Raw,
        conf, get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import config


class PacketInfo:
    """Structured packet information extracted from raw packets."""

    __slots__ = [
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'length', 'flags', 'ttl', 'payload_size',
        'is_encrypted', 'tls_version', 'packet_id', 'src_mac',
        'dst_mac', 'dns_query', 'dns_response', 'icmp_type',
        'arp_op', 'window_size', 'header_length', 'fragment_offset',
    ]

    def __init__(self):
        self.timestamp = time.time()
        self.src_ip = ''
        self.dst_ip = ''
        self.src_port = 0
        self.dst_port = 0
        self.protocol = 'OTHER'
        self.length = 0
        self.flags = ''
        self.ttl = 0
        self.payload_size = 0
        self.is_encrypted = False
        self.tls_version = ''
        self.packet_id = ''
        self.src_mac = ''
        self.dst_mac = ''
        self.dns_query = ''
        self.dns_response = ''
        self.icmp_type = -1
        self.arp_op = 0
        self.window_size = 0
        self.header_length = 0
        self.fragment_offset = 0

    def to_dict(self):
        return {slot: getattr(self, slot) for slot in self.__slots__}


class PacketCaptureEngine:
    """
    Real-time packet capture engine.
    Extracts metadata from packets for analysis without inspecting payloads.

    Capture priority:
      1. Scapy raw capture (requires sudo/root)
      2. tcpdump subprocess capture (works on macOS without sudo for some interfaces)
      3. Simulation mode (last resort, clearly labelled)
    """

    def __init__(self, interface=None, bpf_filter=''):
        self.interface = interface or config.CAPTURE_INTERFACE
        self.bpf_filter = bpf_filter or config.CAPTURE_FILTER
        self.packet_buffer = deque(maxlen=config.PACKET_BUFFER_SIZE)
        self.is_running = False
        self._capture_thread = None
        self._callbacks = []
        self._lock = threading.Lock()
        self._capture_mode = 'none'  # 'scapy', 'tcpdump', 'simulation'

        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocol_counts': defaultdict(int),
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'start_time': None,
            'encrypted_packets': 0,
            'capture_mode': 'none',
        }
        self._pps_counter = 0
        self._bps_counter = 0
        self._last_rate_update = time.time()

    def register_callback(self, callback):
        """Register a callback function that receives PacketInfo objects."""
        self._callbacks.append(callback)

    def start(self):
        """Start packet capture in a background thread."""
        if self.is_running:
            return

        self.is_running = True
        self.stats['start_time'] = time.time()
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name='PacketCaptureThread'
        )
        self._capture_thread.start()

        # Start rate calculation thread
        self._rate_thread = threading.Thread(
            target=self._calculate_rates,
            daemon=True,
            name='RateCalculationThread'
        )
        self._rate_thread.start()

        print(f"[*] Packet capture started on interface: {self.interface or 'default'}")

    def stop(self):
        """Stop packet capture."""
        self.is_running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=3)
        print("[*] Packet capture stopped.")

    def _capture_loop(self):
        """Main capture loop — tries Scapy, then tcpdump, then simulation."""
        # ─── Attempt 1: Scapy raw capture ───────────────────
        if SCAPY_AVAILABLE:
            try:
                self._capture_mode = 'scapy'
                self.stats['capture_mode'] = 'scapy (real traffic)'
                print("[*] Attempting Scapy raw capture (requires sudo)...")
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._process_packet,
                    store=0,
                    stop_filter=lambda _: not self.is_running,
                )
                return  # clean exit (user stopped capture)
            except PermissionError:
                print("[!] Scapy: Permission denied (run with sudo for raw capture).")
            except OSError as e:
                if 'Operation not permitted' in str(e):
                    print("[!] Scapy: Operation not permitted — need root.")
                else:
                    print(f"[!] Scapy capture error: {e}")
            except Exception as e:
                print(f"[!] Scapy capture error: {e}")

        # ─── Attempt 2: tcpdump subprocess (macOS-friendly) ─
        if self._try_tcpdump_capture():
            return  # tcpdump ran successfully

        # ─── Attempt 3: Simulation mode ─────────────────────
        print("[!] No capture method available. Running in SIMULATION mode.")
        print("[!] To capture REAL traffic, run:  sudo python3 app.py")
        self._capture_mode = 'simulation'
        self.stats['capture_mode'] = 'simulation (not real traffic)'
        self._simulate_capture()

    def _try_tcpdump_capture(self):
        """
        Try capturing real traffic via tcpdump subprocess.
        On macOS, tcpdump can capture from certain interfaces without sudo
        (e.g., en0, lo0) because /dev/bpf* permissions allow group access.
        """
        try:
            iface = self.interface or self._get_default_interface()
            if not iface:
                print("[!] tcpdump: No suitable interface found.")
                return False

            cmd = ['tcpdump', '-i', iface, '-l', '-n', '-tt',
                   '-q', '-e']  # -e for Ethernet headers
            if self.bpf_filter:
                cmd.append(self.bpf_filter)

            print(f"[*] Attempting tcpdump capture on interface: {iface}")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # Check if tcpdump started successfully (wait briefly for errors)
            time.sleep(0.5)
            if proc.poll() is not None:
                stderr_output = proc.stderr.read()
                if 'permission' in stderr_output.lower():
                    print(f"[!] tcpdump: Permission denied on {iface}.")
                else:
                    print(f"[!] tcpdump failed: {stderr_output.strip()}")
                return False

            self._capture_mode = 'tcpdump'
            self.stats['capture_mode'] = f'tcpdump on {iface} (real traffic)'
            print(f"[✓] tcpdump capture active on {iface} — capturing REAL traffic!")

            # Parse tcpdump output line by line
            while self.is_running:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                self._parse_tcpdump_line(line.strip())

            proc.terminate()
            proc.wait(timeout=3)
            return True

        except FileNotFoundError:
            print("[!] tcpdump not found on this system.")
            return False
        except Exception as e:
            print(f"[!] tcpdump capture error: {e}")
            return False

    def _get_default_interface(self):
        """Find a usable network interface."""
        import platform
        if platform.system() == 'Darwin':
            # macOS: prefer en0 (Wi-Fi) or en1
            for iface in ['en0', 'en1', 'en2', 'lo0']:
                try:
                    result = subprocess.run(
                        ['ifconfig', iface],
                        capture_output=True, text=True, timeout=2
                    )
                    if result.returncode == 0 and 'inet ' in result.stdout:
                        return iface
                except Exception:
                    pass
        elif platform.system() == 'Linux':
            for iface in ['eth0', 'wlan0', 'ens33', 'enp0s3']:
                try:
                    result = subprocess.run(
                        ['ip', 'addr', 'show', iface],
                        capture_output=True, text=True, timeout=2
                    )
                    if result.returncode == 0 and 'inet ' in result.stdout:
                        return iface
                except Exception:
                    pass
        return None

    def _parse_tcpdump_line(self, line):
        """Parse a tcpdump output line into a PacketInfo."""
        if not line or line.startswith('tcpdump:'):
            return

        try:
            pkt = PacketInfo()
            pkt.packet_id = hashlib.md5(
                f"{time.time()}{line[:40]}".encode()
            ).hexdigest()[:12]

            # tcpdump -n -tt -q -e format example:
            # 1711641234.123456 aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66, ...
            # IP 192.168.1.1.443 > 192.168.1.2.54321: tcp 128
            parts = line.split()
            if len(parts) < 4:
                return

            # Timestamp
            try:
                pkt.timestamp = float(parts[0])
            except (ValueError, IndexError):
                pkt.timestamp = time.time()

            # Try to extract MAC addresses (with -e flag)
            mac_idx = -1
            for i, part in enumerate(parts):
                if '>' in part and ':' in parts[i-1] if i > 0 else False:
                    pkt.src_mac = parts[i-1].rstrip(',')
                    mac_idx = i
                    break

            if mac_idx > 0 and mac_idx + 1 < len(parts):
                pkt.dst_mac = parts[mac_idx + 1].rstrip(',')

            # Find "IP" or "IP6" or "ARP" keyword
            rest = line
            if ' IP ' in line:
                ip_part = line.split(' IP ', 1)[1]
                pkt = self._parse_ip_from_tcpdump(pkt, ip_part)
            elif ' IP6 ' in line:
                ip_part = line.split(' IP6 ', 1)[1]
                pkt = self._parse_ip_from_tcpdump(pkt, ip_part)
            elif ' ARP' in line:
                pkt.protocol = 'ARP'
                if 'who-has' in line:
                    pkt.arp_op = 1
                elif 'reply' in line or 'is-at' in line:
                    pkt.arp_op = 2

            # Try to extract packet length from the line
            for part in reversed(parts):
                try:
                    length = int(part)
                    pkt.length = length
                    break
                except ValueError:
                    continue
            if pkt.length == 0:
                pkt.length = len(line)  # rough estimate

            # Update stats and deliver
            self._update_stats(pkt)
            with self._lock:
                self.packet_buffer.append(pkt)
            for callback in self._callbacks:
                try:
                    callback(pkt)
                except Exception as e:
                    print(f"[!] Callback error: {e}")

        except Exception:
            pass  # Skip malformed lines

    def _parse_ip_from_tcpdump(self, pkt, ip_part):
        """Parse IP addresses and ports from tcpdump IP section."""
        # Format: "src.port > dst.port: proto len"
        parts = ip_part.split()
        if len(parts) >= 3:
            # Source
            src_str = parts[0].rstrip(':').rstrip(',')
            src_ip, src_port = self._split_ip_port(src_str)
            pkt.src_ip = src_ip
            pkt.src_port = src_port

            # Destination  (parts[1] is '>')
            dst_str = parts[2].rstrip(':').rstrip(',')
            dst_ip, dst_port = self._split_ip_port(dst_str)
            pkt.dst_ip = dst_ip
            pkt.dst_port = dst_port

            # Protocol detection
            proto_hint = ' '.join(parts[3:]).lower()
            if 'tcp' in proto_hint:
                pkt.protocol = 'TCP'
                # Extract TCP flags if present
                for flag_str in ['S', 'SA', 'A', 'PA', 'FA', 'R', 'F', 'P']:
                    if f' {flag_str} ' in ip_part or f'Flags [{flag_str}]' in ip_part:
                        pkt.flags = flag_str
                        break
                # Try extracting flags from [S], [S.], [P.], [.], [F.], [R]
                if not pkt.flags:
                    import re
                    flag_match = re.search(r'Flags \[([^\]]+)\]', ip_part)
                    if flag_match:
                        raw_flags = flag_match.group(1)
                        pkt.flags = raw_flags.replace('.', 'A').replace('S', 'S').replace('P', 'P').replace('F', 'F').replace('R', 'R')
            elif 'udp' in proto_hint:
                pkt.protocol = 'UDP'
            elif 'icmp' in proto_hint:
                pkt.protocol = 'ICMP'

            # Higher-level protocol based on port
            if pkt.dst_port == 53 or pkt.src_port == 53:
                pkt.protocol = 'DNS'
            elif pkt.dst_port in (443, 8443, 993, 995):
                pkt.protocol = 'HTTPS'
                pkt.is_encrypted = True
            elif pkt.dst_port == 80 or pkt.src_port == 80:
                pkt.protocol = 'HTTP'
            elif pkt.dst_port == 22 or pkt.src_port == 22:
                pkt.protocol = 'SSH'
                pkt.is_encrypted = True
            elif pkt.dst_port == 21 or pkt.src_port == 21:
                pkt.protocol = 'FTP'

        return pkt

    def _split_ip_port(self, addr_str):
        """Split 'ip.port' or 'ip' into (ip, port)."""
        # IPv4: 192.168.1.1.443 → ('192.168.1.1', 443)
        parts = addr_str.split('.')
        if len(parts) >= 5:
            # Last part is port
            try:
                port = int(parts[-1])
                ip = '.'.join(parts[:-1])
                return ip, port
            except ValueError:
                return addr_str, 0
        elif len(parts) == 4:
            # IP only, no port
            return addr_str, 0
        return addr_str, 0

    def _process_packet(self, packet):
        """Extract metadata from a captured Scapy packet."""
        pkt_info = PacketInfo()
        pkt_info.length = len(packet)
        pkt_info.packet_id = hashlib.md5(
            f"{time.time()}{len(packet)}".encode()
        ).hexdigest()[:12]

        # Ethernet layer
        if packet.haslayer(Ether):
            pkt_info.src_mac = packet[Ether].src
            pkt_info.dst_mac = packet[Ether].dst

        # IP layer
        if packet.haslayer(IP):
            pkt_info.src_ip = packet[IP].src
            pkt_info.dst_ip = packet[IP].dst
            pkt_info.ttl = packet[IP].ttl
            pkt_info.header_length = packet[IP].ihl * 4
            pkt_info.fragment_offset = packet[IP].frag

        # TCP layer
        if packet.haslayer(TCP):
            pkt_info.src_port = packet[TCP].sport
            pkt_info.dst_port = packet[TCP].dport
            pkt_info.flags = str(packet[TCP].flags)
            pkt_info.window_size = packet[TCP].window
            pkt_info.protocol = 'TCP'

            # Detect encrypted traffic (TLS/SSL)
            if packet[TCP].dport in (443, 8443, 993, 995, 465, 587):
                pkt_info.is_encrypted = True
                pkt_info.protocol = 'HTTPS'
                pkt_info.tls_version = self._detect_tls_version(packet)
            elif packet[TCP].dport == 22:
                pkt_info.is_encrypted = True
                pkt_info.protocol = 'SSH'
            elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
                pkt_info.protocol = 'HTTP'
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                pkt_info.protocol = 'FTP'

        # UDP layer
        elif packet.haslayer(UDP):
            pkt_info.src_port = packet[UDP].sport
            pkt_info.dst_port = packet[UDP].dport
            pkt_info.protocol = 'UDP'

        # DNS layer
        if packet.haslayer(DNS):
            pkt_info.protocol = 'DNS'
            try:
                if packet[DNS].qr == 0 and packet[DNS].qd:
                    pkt_info.dns_query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                elif packet[DNS].qr == 1 and packet[DNS].an:
                    pkt_info.dns_response = str(packet[DNS].an.rdata)
            except (AttributeError, IndexError):
                pass

        # ICMP layer
        if packet.haslayer(ICMP):
            pkt_info.protocol = 'ICMP'
            pkt_info.icmp_type = packet[ICMP].type

        # ARP layer
        if packet.haslayer(ARP):
            pkt_info.protocol = 'ARP'
            pkt_info.arp_op = packet[ARP].op
            pkt_info.src_ip = packet[ARP].psrc
            pkt_info.dst_ip = packet[ARP].pdst
            pkt_info.src_mac = packet[ARP].hwsrc
            pkt_info.dst_mac = packet[ARP].hwdst

        # Payload size (without inspecting content)
        if packet.haslayer(Raw):
            pkt_info.payload_size = len(packet[Raw].load)

        # Update stats
        self._update_stats(pkt_info)

        # Add to buffer
        with self._lock:
            self.packet_buffer.append(pkt_info)

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(pkt_info)
            except Exception as e:
                print(f"[!] Callback error: {e}")

    def _detect_tls_version(self, packet):
        """Detect TLS version from packet metadata (not payload)."""
        if packet.haslayer(Raw):
            raw = bytes(packet[Raw].load)
            if len(raw) > 5:
                content_type = raw[0]
                if content_type in (20, 21, 22, 23):  # TLS content types
                    major = raw[1]
                    minor = raw[2]
                    versions = {
                        (3, 0): 'SSL 3.0',
                        (3, 1): 'TLS 1.0',
                        (3, 2): 'TLS 1.1',
                        (3, 3): 'TLS 1.2',
                        (3, 4): 'TLS 1.3',
                    }
                    return versions.get((major, minor), f'Unknown ({major}.{minor})')
        return 'Unknown'

    def _update_stats(self, pkt_info):
        """Update capture statistics."""
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += pkt_info.length
        self.stats['protocol_counts'][pkt_info.protocol] += 1
        if pkt_info.is_encrypted:
            self.stats['encrypted_packets'] += 1
        self._pps_counter += 1
        self._bps_counter += pkt_info.length

    def _calculate_rates(self):
        """Calculate packets/bytes per second periodically."""
        while self.is_running:
            time.sleep(1)
            self.stats['packets_per_second'] = self._pps_counter
            self.stats['bytes_per_second'] = self._bps_counter
            self._pps_counter = 0
            self._bps_counter = 0

    def _simulate_capture(self):
        """Simulate packet capture for testing without root privileges."""
        import random
        import string

        protocols = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'ARP', 'SSH', 'FTP']
        sample_ips = [
            '192.168.1.' + str(i) for i in range(1, 20)
        ] + [
            '10.0.0.' + str(i) for i in range(1, 10)
        ] + [
            '8.8.8.8', '1.1.1.1', '208.67.222.222', '172.217.14.206',
            '151.101.1.69', '104.16.85.20', '13.107.42.14',
        ]

        common_ports = [80, 443, 22, 53, 8080, 3306, 21, 25, 110, 143, 3389, 5432]
        dns_domains = [
            'google.com', 'github.com', 'stackoverflow.com',
            'example.com', 'api.service.local', 'cdn.fast.net',
            'mail.provider.com', 'db.internal.corp',
        ]
        suspicious_domains = [
            'c2.malware.evil', 'exfil.badguy.xyz',
            'a' * 60 + '.suspicious.com',
        ]

        attack_cycle = 0
        while self.is_running:
            attack_cycle += 1

            # Normal traffic
            for _ in range(random.randint(3, 8)):
                pkt = PacketInfo()
                pkt.protocol = random.choice(protocols)
                pkt.src_ip = random.choice(sample_ips)
                pkt.dst_ip = random.choice(sample_ips)
                pkt.src_port = random.randint(1024, 65535)
                pkt.dst_port = random.choice(common_ports)
                pkt.length = random.randint(40, 1500)
                pkt.ttl = random.choice([64, 128, 255])
                pkt.window_size = random.choice([8192, 16384, 32768, 65535])
                pkt.header_length = random.choice([20, 24, 32, 40])
                pkt.payload_size = max(0, pkt.length - pkt.header_length)
                pkt.packet_id = hashlib.md5(
                    f"{time.time()}{random.random()}".encode()
                ).hexdigest()[:12]
                pkt.src_mac = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))
                pkt.dst_mac = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))

                if pkt.protocol == 'HTTPS':
                    pkt.is_encrypted = True
                    pkt.dst_port = 443
                    pkt.tls_version = random.choice(['TLS 1.2', 'TLS 1.3', 'TLS 1.0'])
                elif pkt.protocol == 'SSH':
                    pkt.is_encrypted = True
                    pkt.dst_port = 22
                elif pkt.protocol == 'DNS':
                    pkt.dst_port = 53
                    pkt.dns_query = random.choice(dns_domains)
                elif pkt.protocol == 'HTTP':
                    pkt.dst_port = 80
                    pkt.flags = random.choice(['S', 'SA', 'A', 'PA', 'FA'])
                elif pkt.protocol == 'ICMP':
                    pkt.icmp_type = random.choice([0, 8, 3, 11])
                elif pkt.protocol == 'ARP':
                    pkt.arp_op = random.choice([1, 2])
                elif pkt.protocol in ('TCP', 'FTP'):
                    pkt.flags = random.choice(['S', 'SA', 'A', 'PA', 'FA', 'R'])

                self._update_stats(pkt)
                with self._lock:
                    self.packet_buffer.append(pkt)
                for callback in self._callbacks:
                    try:
                        callback(pkt)
                    except Exception as e:
                        print(f"[!] Callback error: {e}")

            # Simulate occasional attack patterns
            if attack_cycle % 15 == 0:
                # Port scan simulation — fixed src_port so packets build one flow
                scanner_ip = '192.168.1.100'
                target_ip = random.choice(sample_ips)
                scan_src_port = random.randint(40000, 50000)
                for port in random.sample(range(1, 1024), random.randint(15, 25)):
                    pkt = PacketInfo()
                    pkt.protocol = 'TCP'
                    pkt.src_ip = scanner_ip
                    pkt.dst_ip = target_ip
                    pkt.src_port = scan_src_port
                    pkt.dst_port = port
                    pkt.flags = 'S'
                    pkt.length = 54
                    pkt.ttl = 64
                    pkt.packet_id = hashlib.md5(
                        f"{time.time()}{random.random()}".encode()
                    ).hexdigest()[:12]
                    self._update_stats(pkt)
                    with self._lock:
                        self.packet_buffer.append(pkt)
                    for cb in self._callbacks:
                        try:
                            cb(pkt)
                        except Exception:
                            pass

            if attack_cycle % 25 == 0:
                # DNS tunneling simulation — consistent src_port for flow grouping
                dns_src_port = random.randint(40000, 50000)
                for _ in range(random.randint(8, 15)):
                    pkt = PacketInfo()
                    pkt.protocol = 'DNS'
                    pkt.src_ip = '192.168.1.50'
                    pkt.dst_ip = '8.8.8.8'
                    pkt.src_port = dns_src_port
                    pkt.dst_port = 53
                    pkt.dns_query = random.choice(suspicious_domains)
                    pkt.length = random.randint(200, 500)
                    pkt.packet_id = hashlib.md5(
                        f"{time.time()}{random.random()}".encode()
                    ).hexdigest()[:12]
                    self._update_stats(pkt)
                    with self._lock:
                        self.packet_buffer.append(pkt)
                    for cb in self._callbacks:
                        try:
                            cb(pkt)
                        except Exception:
                            pass

            if attack_cycle % 35 == 0:
                # SYN flood simulation — use a small pool of attacker IPs
                # so flows build up enough for ML to analyze them
                flood_target = random.choice(sample_ips)
                flood_attacker_ips = [
                    f'10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}'
                    for _ in range(random.randint(3, 5))
                ]
                flood_src_port = random.randint(30000, 40000)
                for i in range(random.randint(80, 150)):
                    pkt = PacketInfo()
                    pkt.protocol = 'TCP'
                    pkt.src_ip = flood_attacker_ips[i % len(flood_attacker_ips)]
                    pkt.dst_ip = flood_target
                    pkt.src_port = flood_src_port
                    pkt.dst_port = 80
                    pkt.flags = 'S'
                    pkt.length = 54
                    pkt.ttl = random.randint(30, 128)
                    pkt.packet_id = hashlib.md5(
                        f"{time.time()}{random.random()}".encode()
                    ).hexdigest()[:12]
                    self._update_stats(pkt)
                    with self._lock:
                        self.packet_buffer.append(pkt)
                    for cb in self._callbacks:
                        try:
                            cb(pkt)
                        except Exception:
                            pass

            if attack_cycle % 40 == 0:
                # Encrypted traffic anomaly (old TLS) — fixed destination for flow grouping
                enc_target = random.choice(sample_ips)
                enc_src_port = random.randint(50000, 60000)
                for _ in range(random.randint(5, 12)):
                    pkt = PacketInfo()
                    pkt.protocol = 'HTTPS'
                    pkt.src_ip = '192.168.1.77'
                    pkt.dst_ip = enc_target
                    pkt.src_port = enc_src_port
                    pkt.dst_port = 443
                    pkt.is_encrypted = True
                    pkt.tls_version = random.choice(['SSL 3.0', 'TLS 1.0'])
                    pkt.length = random.randint(100, 800)
                    pkt.flags = 'PA'
                    pkt.packet_id = hashlib.md5(
                        f"{time.time()}{random.random()}".encode()
                    ).hexdigest()[:12]
                    self._update_stats(pkt)
                    with self._lock:
                        self.packet_buffer.append(pkt)
                    for cb in self._callbacks:
                        try:
                            cb(pkt)
                        except Exception:
                            pass

            time.sleep(random.uniform(0.3, 0.8))

    def get_stats(self):
        """Return current capture statistics."""
        stats = dict(self.stats)
        stats['protocol_counts'] = dict(stats['protocol_counts'])
        if stats['start_time']:
            stats['uptime'] = time.time() - stats['start_time']
        else:
            stats['uptime'] = 0
        return stats

    def get_recent_packets(self, count=50):
        """Return the most recent packets."""
        with self._lock:
            packets = list(self.packet_buffer)[-count:]
        return [p.to_dict() for p in packets]

    def get_available_interfaces(self):
        """List available network interfaces."""
        if SCAPY_AVAILABLE:
            return get_if_list()
        # Fallback: use ifconfig/ip to list interfaces
        import platform
        if platform.system() == 'Darwin':
            try:
                result = subprocess.run(
                    ['networksetup', '-listallhardwareports'],
                    capture_output=True, text=True, timeout=3
                )
                ifaces = []
                for line in result.stdout.split('\n'):
                    if line.startswith('Device:'):
                        ifaces.append(line.split(':')[1].strip())
                return ifaces if ifaces else ['en0', 'en1', 'lo0']
            except Exception:
                pass
        return ['eth0', 'wlan0', 'lo0']
