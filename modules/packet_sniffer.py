#!/usr/bin/env python3
"""
Mauritania Eye - Packet Sniffer Module
Real-time network traffic analysis and packet capture

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
import threading
from collections import defaultdict, deque

class PacketSniffer:
    """
    Advanced packet sniffing and analysis module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.running = False
        self.packets_captured = 0
        self.packet_stats = defaultdict(int)
        self.recent_packets = deque(maxlen=100)
        self.suspicious_activity = []
        
        # Traffic analysis
        self.traffic_by_protocol = defaultdict(int)
        self.traffic_by_port = defaultdict(int)
        self.traffic_by_ip = defaultdict(int)
        
    async def start_sniffing(self, interface="eth0", duration=60, filter_str=""):
        """Start packet sniffing with real-time analysis"""
        self.console.print(Panel(f"🔍 Starting Packet Capture on {interface}", style="bold green"))
        
        self.running = True
        self.packets_captured = 0
        
        # Start sniffing in a separate thread
        sniff_thread = threading.Thread(
            target=self._sniff_packets,
            args=(interface, filter_str),
            daemon=True
        )
        sniff_thread.start()
        
        # Display real-time statistics
        await self._display_realtime_stats(duration)
        
        self.running = False
        await self._generate_packet_report()
    
    def _sniff_packets(self, interface, filter_str):
        """Packet sniffing worker function"""
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                filter=filter_str,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            self.logger.log_error("PacketSniffer", f"Sniffing error: {str(e)}")
    
    def _process_packet(self, packet):
        """Process and analyze each captured packet"""
        self.packets_captured += 1
        
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'protocols': []
        }
        
        # Analyze packet layers
        if IP in packet:
            ip_layer = packet[IP]
            packet_info.update({
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto
            })
            
            self.traffic_by_ip[ip_layer.src] += 1
            self.traffic_by_ip[ip_layer.dst] += 1
            
            # Protocol-specific analysis
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_info.update({
                    'src_port': tcp_layer.sport,
                    'dst_port': tcp_layer.dport,
                    'flags': tcp_layer.flags
                })
                self.traffic_by_protocol['TCP'] += 1
                self.traffic_by_port[tcp_layer.dport] += 1
                
                # Detect suspicious TCP activity
                self._detect_tcp_anomalies(packet_info, tcp_layer)
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_info.update({
                    'src_port': udp_layer.sport,
                    'dst_port': udp_layer.dport
                })
                self.traffic_by_protocol['UDP'] += 1
                self.traffic_by_port[udp_layer.dport] += 1
                
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                packet_info.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code
                })
                self.traffic_by_protocol['ICMP'] += 1
        
        elif ARP in packet:
            arp_layer = packet[ARP]
            packet_info.update({
                'arp_op': arp_layer.op,
                'src_mac': arp_layer.hwsrc,
                'dst_mac': arp_layer.hwdst,
                'src_ip': arp_layer.psrc,
                'dst_ip': arp_layer.pdst
            })
            self.traffic_by_protocol['ARP'] += 1
            
            # Detect ARP spoofing
            self._detect_arp_anomalies(packet_info, arp_layer)
        
        # DNS analysis
        if DNS in packet:
            dns_layer = packet[DNS]
            if dns_layer.qr == 0:  # Query
                packet_info['dns_query'] = dns_layer.qd.qname.decode('utf-8')
            self.traffic_by_protocol['DNS'] += 1
        
        # Store packet info
        self.recent_packets.append(packet_info)
        
        # Log to file
        self.logger.log_packet(packet_info)
    
    def _detect_tcp_anomalies(self, packet_info, tcp_layer):
        """Detect suspicious TCP activity"""
        # Port scanning detection
        if tcp_layer.flags == 2:  # SYN flag only
            self.packet_stats['syn_packets'] += 1
        
        # Common attack ports
        suspicious_ports = [22, 23, 80, 443, 3389, 5900, 1433, 3306]
        if tcp_layer.dport in suspicious_ports:
            self.suspicious_activity.append({
                'type': 'suspicious_port_access',
                'timestamp': packet_info['timestamp'],
                'src_ip': packet_info['src_ip'],
                'dst_port': tcp_layer.dport
            })
    
    def _detect_arp_anomalies(self, packet_info, arp_layer):
        """Detect ARP spoofing attempts"""
        if arp_layer.op == 2:  # ARP reply
            # Check for duplicate IP-MAC mappings
            key = f"{arp_layer.psrc}_{arp_layer.hwsrc}"
            if key not in self.packet_stats:
                self.packet_stats[key] = 0
            self.packet_stats[key] += 1
    
    async def _display_realtime_stats(self, duration):
        """Display real-time packet statistics"""
        start_time = time.time()
        
        def generate_stats_table():
            table = Table(title="📊 Real-time Packet Statistics")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="yellow")
            
            table.add_row("Packets Captured", str(self.packets_captured))
            table.add_row("Capture Rate", f"{self.packets_captured/(time.time()-start_time+1):.1f} pps")
            
            # Protocol distribution
            for protocol, count in self.traffic_by_protocol.items():
                table.add_row(f"{protocol} Packets", str(count))
            
            # Top talkers
            if self.traffic_by_ip:
                top_ip = max(self.traffic_by_ip.items(), key=lambda x: x[1])
                table.add_row("Top Talker", f"{top_ip[0]} ({top_ip[1]} packets)")
            
            # Suspicious activity
            table.add_row("Suspicious Events", str(len(self.suspicious_activity)))
            
            return table
        
        with Live(generate_stats_table(), refresh_per_second=2) as live:
            while self.running and (time.time() - start_time) < duration:
                await asyncio.sleep(0.5)
                live.update(generate_stats_table())
    
    async def _generate_packet_report(self):
        """Generate comprehensive packet analysis report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': self.packets_captured,
            'protocol_distribution': dict(self.traffic_by_protocol),
            'top_ports': dict(sorted(self.traffic_by_port.items(), 
                                   key=lambda x: x[1], reverse=True)[:10]),
            'top_ips': dict(sorted(self.traffic_by_ip.items(), 
                                 key=lambda x: x[1], reverse=True)[:10]),
            'suspicious_activity': self.suspicious_activity,
            'recent_packets': list(self.recent_packets)[-20:]  # Last 20 packets
        }
        
        await self.logger.save_report(report, "packet_analysis")
        
        # Display summary
        self._display_packet_summary(report)
    
    def _display_packet_summary(self, report):
        """Display packet analysis summary"""
        self.console.print(Panel("📋 Packet Analysis Summary", style="bold blue"))
        
        # Protocol distribution table
        proto_table = Table(title="Protocol Distribution")
        proto_table.add_column("Protocol", style="cyan")
        proto_table.add_column("Packets", style="yellow")
        proto_table.add_column("Percentage", style="green")
        
        total = report['total_packets']
        for protocol, count in report['protocol_distribution'].items():
            percentage = (count / total * 100) if total > 0 else 0
            proto_table.add_row(protocol, str(count), f"{percentage:.1f}%")
        
        self.console.print(proto_table)
        
        # Top ports table
        if report['top_ports']:
            port_table = Table(title="Top Destination Ports")
            port_table.add_column("Port", style="cyan")
            port_table.add_column("Packets", style="yellow")
            
            for port, count in list(report['top_ports'].items())[:5]:
                port_table.add_row(str(port), str(count))
            
            self.console.print(port_table)
        
        # Suspicious activity
        if report['suspicious_activity']:
            self.console.print(f"[red]⚠️ {len(report['suspicious_activity'])} suspicious events detected![/red]")
            for event in report['suspicious_activity'][:5]:
                self.console.print(f"  • {event['type']}: {event['src_ip']} -> Port {event.get('dst_port', 'N/A')}")