"""
Network Traffic Capture

Captures and analyzes network packets for security threats.
Detects port scans, SYN floods, and unusual network activity.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading
import time


class NetworkCapture:
    """Capture and analyze network traffic for threats"""
    
    def __init__(self, callback=None, interface=None):
        """
        Initialize Network Capture
        
        Args:
            callback: Function to call with detected threats
            interface: Network interface to capture on (None = all)
        """
        self.callback = callback
        self.interface = interface
        self.running = False
        self.thread = None
        
        # Track connections for pattern detection
        self.connections = defaultdict(lambda: {"count": 0, "ports": set(), "last_seen": datetime.now()})
        self.syn_packets = defaultdict(lambda: {"count": 0, "last_seen": datetime.now()})
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 10  # ports in 60 seconds
        self.SYN_FLOOD_THRESHOLD = 50  # SYN packets in 10 seconds
        
    def start(self, packet_count=0, timeout=None):
        """
        Start packet capture
        
        Args:
            packet_count: Number of packets to capture (0 = infinite)
            timeout: Capture timeout in seconds (None = no timeout)
        """
        if self.running:
            print("[NetworkCapture] Already running")
            return
        
        self.running = True
        self.thread = threading.Thread(
            target=self._capture_loop,
            args=(packet_count, timeout),
            daemon=True
        )
        self.thread.start()
        print(f"[NetworkCapture] Started capturing on interface: {self.interface or 'all'}")
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[NetworkCapture] Stopped")
    
    def _capture_loop(self, packet_count, timeout):
        """Main capture loop"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                count=packet_count,
                timeout=timeout,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"[NetworkCapture] Error: {e}")
            print("[NetworkCapture] Note: Packet capture requires administrator/root privileges")
    
    def _process_packet(self, packet):
        """
        Process a captured packet
        
        Args:
            packet: Scapy packet object
        """
        try:
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # TCP packets
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                self._process_tcp(src_ip, dst_ip, tcp_layer)
            
            # UDP packets
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                self._process_udp(src_ip, dst_ip, udp_layer)
            
            # ICMP packets
            elif packet.haslayer(ICMP):
                self._process_icmp(src_ip, dst_ip, packet[ICMP])
            
            # Cleanup old entries
            self._cleanup_old_entries()
            
        except Exception as e:
            print(f"[NetworkCapture] Error processing packet: {e}")
    
    def _process_tcp(self, src_ip: str, dst_ip: str, tcp_layer):
        """Process TCP packet"""
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags
        
        # Track connections
        conn_key = f"{src_ip}->{dst_ip}"
        self.connections[conn_key]["count"] += 1
        self.connections[conn_key]["ports"].add(dst_port)
        self.connections[conn_key]["last_seen"] = datetime.now()
        
        # Detect port scan (many different ports from same source)
        if len(self.connections[conn_key]["ports"]) >= self.PORT_SCAN_THRESHOLD:
            self._report_threat({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "ports_scanned": len(self.connections[conn_key]["ports"]),
                "message": f"Port scan detected from {src_ip} to {dst_ip} ({len(self.connections[conn_key]['ports'])} ports)"
            })
            # Reset to avoid duplicate alerts
            self.connections[conn_key]["ports"] = set()
        
        # Detect SYN flood (many SYN packets)
        if flags & 0x02:  # SYN flag
            syn_key = f"{src_ip}->{dst_ip}:{dst_port}"
            self.syn_packets[syn_key]["count"] += 1
            self.syn_packets[syn_key]["last_seen"] = datetime.now()
            
            if self.syn_packets[syn_key]["count"] >= self.SYN_FLOOD_THRESHOLD:
                self._report_threat({
                    "type": "SYN_FLOOD",
                    "severity": "CRITICAL",
                    "source_ip": src_ip,
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                    "packet_count": self.syn_packets[syn_key]["count"],
                    "message": f"SYN flood detected from {src_ip} to {dst_ip}:{dst_port} ({self.syn_packets[syn_key]['count']} packets)"
                })
                # Reset
                self.syn_packets[syn_key]["count"] = 0
    
    def _process_udp(self, src_ip: str, dst_ip: str, udp_layer):
        """Process UDP packet"""
        dst_port = udp_layer.dport
        
        # Track for potential UDP flood
        conn_key = f"{src_ip}->{dst_ip}"
        self.connections[conn_key]["count"] += 1
        self.connections[conn_key]["ports"].add(dst_port)
        self.connections[conn_key]["last_seen"] = datetime.now()
    
    def _process_icmp(self, src_ip: str, dst_ip: str, icmp_layer):
        """Process ICMP packet"""
        # Could detect ICMP floods or ping sweeps
        pass
    
    def _cleanup_old_entries(self):
        """Remove old tracking entries"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=60)
        
        # Cleanup connections
        to_remove = [k for k, v in self.connections.items() if v["last_seen"] < cutoff]
        for k in to_remove:
            del self.connections[k]
        
        # Cleanup SYN packets
        cutoff_syn = now - timedelta(seconds=10)
        to_remove = [k for k, v in self.syn_packets.items() if v["last_seen"] < cutoff_syn]
        for k in to_remove:
            del self.syn_packets[k]
    
    def _report_threat(self, threat_data: Dict):
        """Report detected threat"""
        normalized = {
            "timestamp": datetime.now().isoformat(),
            "source": "network_capture",
            "severity": threat_data["severity"],
            "source_ip": threat_data["source_ip"],
            "threat_type": threat_data["type"],
            "message": threat_data["message"],
            "raw_data": threat_data
        }
        
        if self.callback:
            self.callback(normalized)
        else:
            print(f"\n[THREAT] {threat_data['message']}")
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        return {
            "active_connections": len(self.connections),
            "tracked_syn_flows": len(self.syn_packets),
            "total_ports_seen": sum(len(v["ports"]) for v in self.connections.values())
        }


# Test function
if __name__ == "__main__":
    def print_threat(threat):
        print(f"\n[NETWORK THREAT]")
        print(f"  Type: {threat['threat_type']}")
        print(f"  Severity: {threat['severity']}")
        print(f"  Source: {threat['source_ip']}")
        print(f"  Message: {threat['message']}")
    
    print("Testing Network Capture...")
    print("Note: Requires Administrator/Root privileges!")
    print("\nStarting packet capture (Ctrl+C to stop)...")
    
    capture = NetworkCapture(callback=print_threat)
    capture.start(timeout=30)  # Capture for 30 seconds
    
    try:
        while capture.running:
            time.sleep(1)
            stats = capture.get_statistics()
            print(f"\rActive connections: {stats['active_connections']}, Ports seen: {stats['total_ports_seen']}", end="")
    except KeyboardInterrupt:
        print("\nStopping...")
    
    capture.stop()
