#!/usr/bin/env python3
"""
Mauritania Eye - Spoofing Detector Module
ARP and DNS spoofing detection

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import time
from datetime import datetime
from scapy.all import sniff, ARP, DNS, IP, UDP
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import threading
from collections import defaultdict

class SpoofingDetector:
    """
    ARP and DNS spoofing detection module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.running = False
        
        # ARP monitoring
        self.arp_table = {}  # IP -> MAC mapping
        self.arp_history = defaultdict(list)  # Track MAC changes
        self.arp_alerts = []
        
        # DNS monitoring
        self.dns_responses = defaultdict(list)  # Domain -> IP mappings
        self.dns_alerts = []
        
        # Legitimate DNS servers (to be populated)
        self.legitimate_dns_servers = set()
        
    async def start_detection(self, interface="eth0", duration=300):
        """Start spoofing detection"""
        self.console.print(Panel("🛡️ Starting Spoofing Detection", style="bold red"))
        
        self.running = True
        
        # Start packet sniffing in separate thread
        sniff_thread = threading.Thread(
            target=self._sniff_spoofing_packets,
            args=(interface,),
            daemon=True
        )
        sniff_thread.start()
        
        # Monitor for specified duration
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            await asyncio.sleep(5)
            await self._analyze_spoofing_patterns()
            self._display_detection_status()
        
        self.running = False
        await self._generate_spoofing_report()
    
    def _sniff_spoofing_packets(self, interface):
        """Sniff packets for spoofing analysis"""
        try:
            sniff(
                iface=interface,
                prn=self._process_spoofing_packet,
                filter="arp or (udp and port 53)",
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            self.logger.log_error("SpoofingDetector", f"Sniffing error: {str(e)}")
    
    def _process_spoofing_packet(self, packet):
        """Process packets for spoofing indicators"""
        timestamp = datetime.now()
        
        if ARP in packet:
            self._process_arp_packet(packet, timestamp)
        elif DNS in packet and UDP in packet:
            self._process_dns_packet(packet, timestamp)
    
    def _process_arp_packet(self, packet, timestamp):
        """Process ARP packets for spoofing detection"""
        arp_layer = packet[ARP]
        
        # Only process ARP replies
        if arp_layer.op == 2:  # ARP reply
            ip = arp_layer.psrc
            mac = arp_layer.hwsrc
            
            # Check if we've seen this IP before
            if ip in self.arp_table:
                previous_mac = self.arp_table[ip]
                
                # MAC address changed - potential ARP spoofing
                if previous_mac != mac:
                    alert = {
                        'timestamp': timestamp.isoformat(),
                        'type': 'arp_spoofing',
                        'ip': ip,
                        'old_mac': previous_mac,
                        'new_mac': mac,
                        'severity': 'high'
                    }
                    
                    self.arp_alerts.append(alert)
                    self.logger.log_alert("SpoofingDetector", alert)
                    
                    # Add to history
                    self.arp_history[ip].append({
                        'timestamp': timestamp,
                        'mac': mac,
                        'event': 'mac_change'
                    })
            
            # Update ARP table
            self.arp_table[ip] = mac
            
            # Track all MAC addresses for this IP
            if ip not in self.arp_history:
                self.arp_history[ip] = []
            
            self.arp_history[ip].append({
                'timestamp': timestamp,
                'mac': mac,
                'event': 'arp_reply'
            })
    
    def _process_dns_packet(self, packet, timestamp):
        """Process DNS packets for spoofing detection"""
        dns_layer = packet[DNS]
        ip_layer = packet[IP]
        
        # Only process DNS responses
        if dns_layer.qr == 1:  # DNS response
            # Extract query name and response IPs
            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                
                # Extract answer IPs
                response_ips = []
                if dns_layer.ancount > 0:
                    for i in range(dns_layer.ancount):
                        if hasattr(dns_layer.an[i], 'rdata'):
                            response_ips.append(str(dns_layer.an[i].rdata))
                
                # Check for suspicious DNS responses
                self._check_dns_spoofing(
                    query_name, 
                    response_ips, 
                    ip_layer.src, 
                    timestamp
                )
                
                # Store DNS response
                for ip in response_ips:
                    self.dns_responses[query_name].append({
                        'timestamp': timestamp,
                        'ip': ip,
                        'dns_server': ip_layer.src
                    })
    
    def _check_dns_spoofing(self, domain, response_ips, dns_server, timestamp):
        """Check for DNS spoofing indicators"""
        # Check if we've seen different IPs for this domain
        if domain in self.dns_responses:
            previous_responses = self.dns_responses[domain]
            previous_ips = set(resp['ip'] for resp in previous_responses)
            current_ips = set(response_ips)
            
            # Check for IP changes
            if previous_ips and not current_ips.intersection(previous_ips):
                alert = {
                    'timestamp': timestamp.isoformat(),
                    'type': 'dns_spoofing',
                    'domain': domain,
                    'previous_ips': list(previous_ips),
                    'new_ips': response_ips,
                    'dns_server': dns_server,
                    'severity': 'medium'
                }
                
                self.dns_alerts.append(alert)
                self.logger.log_alert("SpoofingDetector", alert)
        
        # Check for suspicious DNS servers
        if self.legitimate_dns_servers and dns_server not in self.legitimate_dns_servers:
            # Check if this is a local response (potential DNS hijacking)
            if self._is_local_ip(dns_server):
                alert = {
                    'timestamp': timestamp.isoformat(),
                    'type': 'suspicious_dns_server',
                    'domain': domain,
                    'dns_server': dns_server,
                    'response_ips': response_ips,
                    'severity': 'medium'
                }
                
                self.dns_alerts.append(alert)
                self.logger.log_alert("SpoofingDetector", alert)
    
    def _is_local_ip(self, ip):
        """Check if IP is in local network ranges"""
        local_ranges = [
            '192.168.',
            '10.',
            '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.',
            '172.24.', '172.25.', '172.26.', '172.27.',
            '172.28.', '172.29.', '172.30.', '172.31.'
        ]
        
        return any(ip.startswith(prefix) for prefix in local_ranges)
    
    async def _analyze_spoofing_patterns(self):
        """Analyze patterns for advanced spoofing detection"""
        # Analyze ARP patterns
        await self._analyze_arp_patterns()
        
        # Analyze DNS patterns
        await self._analyze_dns_patterns()
    
    async def _analyze_arp_patterns(self):
        """Analyze ARP traffic patterns"""
        current_time = time.time()
        
        # Check for rapid ARP changes (potential ARP storm)
        for ip, history in self.arp_history.items():
            recent_events = [
                event for event in history 
                if (current_time - event['timestamp'].timestamp()) < 60  # Last minute
            ]
            
            if len(recent_events) > 10:  # More than 10 ARP events in a minute
                alert = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'arp_storm',
                    'ip': ip,
                    'event_count': len(recent_events),
                    'severity': 'medium'
                }
                
                self.arp_alerts.append(alert)
                self.logger.log_alert("SpoofingDetector", alert)
    
    async def _analyze_dns_patterns(self):
        """Analyze DNS response patterns"""
        # Check for domains with multiple conflicting responses
        for domain, responses in self.dns_responses.items():
            if len(responses) > 1:
                unique_ips = set(resp['ip'] for resp in responses)
                unique_servers = set(resp['dns_server'] for resp in responses)
                
                # Multiple IPs from different servers - potential DNS poisoning
                if len(unique_ips) > 1 and len(unique_servers) > 1:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'dns_poisoning',
                        'domain': domain,
                        'conflicting_ips': list(unique_ips),
                        'dns_servers': list(unique_servers),
                        'severity': 'high'
                    }
                    
                    self.dns_alerts.append(alert)
                    self.logger.log_alert("SpoofingDetector", alert)
    
    def _display_detection_status(self):
        """Display current detection status"""
        # Clear screen and show status
        self.console.clear()
        self.console.print(Panel("🛡️ Spoofing Detection Status", style="bold blue"))
        
        # ARP monitoring status
        arp_table = Table(title="ARP Monitoring")
        arp_table.add_column("Metric", style="cyan")
        arp_table.add_column("Value", style="yellow")
        
        arp_table.add_row("Tracked IPs", str(len(self.arp_table)))
        arp_table.add_row("ARP Alerts", str(len(self.arp_alerts)))
        arp_table.add_row("Recent ARP Changes", str(len([a for a in self.arp_alerts if a['type'] == 'arp_spoofing'])))
        
        self.console.print(arp_table)
        
        # DNS monitoring status
        dns_table = Table(title="DNS Monitoring")
        dns_table.add_column("Metric", style="cyan")
        dns_table.add_column("Value", style="yellow")
        
        dns_table.add_row("Tracked Domains", str(len(self.dns_responses)))
        dns_table.add_row("DNS Alerts", str(len(self.dns_alerts)))
        dns_table.add_row("Suspicious Responses", str(len([a for a in self.dns_alerts if a['type'] == 'dns_spoofing'])))
        
        self.console.print(dns_table)
        
        # Recent alerts
        if self.arp_alerts or self.dns_alerts:
            recent_alerts = (self.arp_alerts + self.dns_alerts)[-5:]  # Last 5 alerts
            
            alerts_table = Table(title="Recent Alerts")
            alerts_table.add_column("Time", style="cyan")
            alerts_table.add_column("Type", style="red")
            alerts_table.add_column("Details", style="white")
            
            for alert in recent_alerts:
                timestamp = alert['timestamp'][:19]  # Remove microseconds
                alert_type = alert['type'].replace('_', ' ').title()
                
                if alert['type'] == 'arp_spoofing':
                    details = f"IP {alert['ip']}: {alert['old_mac']} -> {alert['new_mac']}"
                elif alert['type'] == 'dns_spoofing':
                    details = f"Domain {alert['domain']}: IP changed"
                else:
                    details = str(alert.get('ip', alert.get('domain', 'Unknown')))
                
                alerts_table.add_row(timestamp, alert_type, details)
            
            self.console.print(alerts_table)
    
    async def _generate_spoofing_report(self):
        """Generate comprehensive spoofing detection report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'monitoring_duration': 'N/A',  # Could calculate from start time
            'arp_monitoring': {
                'tracked_ips': len(self.arp_table),
                'total_alerts': len(self.arp_alerts),
                'spoofing_attempts': len([a for a in self.arp_alerts if a['type'] == 'arp_spoofing']),
                'arp_storms': len([a for a in self.arp_alerts if a['type'] == 'arp_storm']),
                'arp_table': dict(self.arp_table),
                'alerts': self.arp_alerts
            },
            'dns_monitoring': {
                'tracked_domains': len(self.dns_responses),
                'total_alerts': len(self.dns_alerts),
                'spoofing_attempts': len([a for a in self.dns_alerts if a['type'] == 'dns_spoofing']),
                'poisoning_attempts': len([a for a in self.dns_alerts if a['type'] == 'dns_poisoning']),
                'suspicious_servers': len([a for a in self.dns_alerts if a['type'] == 'suspicious_dns_server']),
                'alerts': self.dns_alerts
            }
        }
        
        await self.logger.save_report(report, "spoofing_detection")
        self._display_spoofing_summary(report)
    
    def _display_spoofing_summary(self, report):
        """Display spoofing detection summary"""
        self.console.print(Panel("📋 Spoofing Detection Summary", style="bold green"))
        
        arp_data = report['arp_monitoring']
        dns_data = report['dns_monitoring']
        
        # Summary table
        summary_table = Table(title="Detection Summary")
        summary_table.add_column("Category", style="cyan")
        summary_table.add_column("Tracked Items", style="yellow")
        summary_table.add_column("Total Alerts", style="red")
        summary_table.add_column("Spoofing Attempts", style="bright_red")
        
        summary_table.add_row(
            "ARP Monitoring",
            str(arp_data['tracked_ips']),
            str(arp_data['total_alerts']),
            str(arp_data['spoofing_attempts'])
        )
        
        summary_table.add_row(
            "DNS Monitoring",
            str(dns_data['tracked_domains']),
            str(dns_data['total_alerts']),
            str(dns_data['spoofing_attempts'])
        )
        
        self.console.print(summary_table)
        
        # Alert breakdown
        total_alerts = arp_data['total_alerts'] + dns_data['total_alerts']
        if total_alerts > 0:
            self.console.print(f"\n[red]⚠️ Total Security Alerts: {total_alerts}[/red]")
            
            if arp_data['spoofing_attempts'] > 0:
                self.console.print(f"  • ARP Spoofing Attempts: {arp_data['spoofing_attempts']}")
            
            if dns_data['spoofing_attempts'] > 0:
                self.console.print(f"  • DNS Spoofing Attempts: {dns_data['spoofing_attempts']}")
            
            if dns_data['poisoning_attempts'] > 0:
                self.console.print(f"  • DNS Poisoning Attempts: {dns_data['poisoning_attempts']}")
        else:
            self.console.print("[green]✅ No spoofing attempts detected[/green]")