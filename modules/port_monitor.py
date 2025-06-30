#!/usr/bin/env python3
"""
Mauritania Eye - Port Monitor Module
Real-time port and service monitoring

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import socket
import psutil
import subprocess
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
import time

class PortMonitor:
    """
    Port and service monitoring module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.running = False
        self.monitored_ports = {}
        self.port_history = {}
        
    async def monitor_ports(self, duration=60, interval=5):
        """Monitor system ports and services"""
        self.console.print(Panel("🔍 Starting Port Monitoring", style="bold green"))
        
        self.running = True
        start_time = time.time()
        
        def generate_port_table():
            # Get current connections
            connections = self._get_network_connections()
            listening_ports = self._get_listening_ports()
            
            # Create main table
            table = Table(title="🔌 Active Network Connections")
            table.add_column("Local Address", style="cyan")
            table.add_column("Remote Address", style="yellow")
            table.add_column("Status", style="green")
            table.add_column("PID", style="magenta")
            table.add_column("Process", style="white")
            
            for conn in connections[:20]:  # Show top 20
                table.add_row(
                    f"{conn['local_ip']}:{conn['local_port']}",
                    f"{conn['remote_ip']}:{conn['remote_port']}" if conn['remote_ip'] else "-",
                    conn['status'],
                    str(conn['pid']) if conn['pid'] else "-",
                    conn['process_name'] or "Unknown"
                )
            
            return table
        
        # Display real-time monitoring
        with Live(generate_port_table(), refresh_per_second=1) as live:
            while self.running and (time.time() - start_time) < duration:
                await asyncio.sleep(interval)
                live.update(generate_port_table())
                
                # Log current state
                await self._log_port_state()
        
        self.running = False
        await self._generate_port_report()
    
    def _get_network_connections(self):
        """Get current network connections"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'local_ip': conn.laddr.ip if conn.laddr else '',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip if conn.raddr else '',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process_name': ''
                }
                
                # Get process name
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        conn_info['process_name'] = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                connections.append(conn_info)
                
        except Exception as e:
            self.logger.log_error("PortMonitor", f"Error getting connections: {str(e)}")
        
        return connections
    
    def _get_listening_ports(self):
        """Get ports in listening state"""
        listening = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    port_info = {
                        'port': conn.laddr.port,
                        'ip': conn.laddr.ip,
                        'pid': conn.pid,
                        'process_name': ''
                    }
                    
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            port_info['process_name'] = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    listening.append(port_info)
                    
        except Exception as e:
            self.logger.log_error("PortMonitor", f"Error getting listening ports: {str(e)}")
        
        return listening
    
    async def _log_port_state(self):
        """Log current port state for analysis"""
        timestamp = datetime.now().isoformat()
        
        port_state = {
            'timestamp': timestamp,
            'connections': self._get_network_connections(),
            'listening_ports': self._get_listening_ports(),
            'system_stats': self._get_system_stats()
        }
        
        # Store in history
        self.port_history[timestamp] = port_state
        
        # Log to file
        await self.logger.log_port_activity(port_state)
    
    def _get_system_stats(self):
        """Get system network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv,
                'errin': net_io.errin,
                'errout': net_io.errout,
                'dropin': net_io.dropin,
                'dropout': net_io.dropout
            }
        except Exception:
            return {}
    
    async def scan_port_range(self, target, start_port=1, end_port=1000):
        """Scan a range of ports on target"""
        self.console.print(Panel(f"🎯 Scanning ports {start_port}-{end_port} on {target}", style="bold yellow"))
        
        open_ports = []
        
        async def scan_port(port):
            try:
                # Create socket with timeout
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    # Port is open, try to identify service
                    service_info = await self._identify_service(target, port)
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': service_info.get('service', 'unknown'),
                        'version': service_info.get('version', ''),
                        'banner': service_info.get('banner', '')
                    })
                    
            except Exception:
                pass
        
        # Scan ports concurrently (in batches to avoid overwhelming)
        batch_size = 50
        for i in range(start_port, end_port + 1, batch_size):
            batch_end = min(i + batch_size, end_port + 1)
            tasks = [scan_port(port) for port in range(i, batch_end)]
            await asyncio.gather(*tasks)
        
        # Display results
        self._display_port_scan_results(target, open_ports)
        
        return open_ports
    
    async def _identify_service(self, target, port):
        """Try to identify service running on port"""
        service_info = {'service': 'unknown', 'version': '', 'banner': ''}
        
        try:
            # Try to grab banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            service_info['banner'] = banner[:100]  # First 100 chars
            
            # Identify common services
            if port == 22:
                service_info['service'] = 'SSH'
            elif port == 23:
                service_info['service'] = 'Telnet'
            elif port == 25:
                service_info['service'] = 'SMTP'
            elif port == 53:
                service_info['service'] = 'DNS'
            elif port in [80, 8080]:
                service_info['service'] = 'HTTP'
                if 'Server:' in banner:
                    server_line = [line for line in banner.split('\n') if 'Server:' in line]
                    if server_line:
                        service_info['version'] = server_line[0].split('Server:')[1].strip()
            elif port == 443:
                service_info['service'] = 'HTTPS'
            elif port == 993:
                service_info['service'] = 'IMAPS'
            elif port == 995:
                service_info['service'] = 'POP3S'
            elif port == 3389:
                service_info['service'] = 'RDP'
            elif port == 5900:
                service_info['service'] = 'VNC'
                
        except Exception:
            pass
        
        return service_info
    
    def _display_port_scan_results(self, target, open_ports):
        """Display port scan results"""
        if not open_ports:
            self.console.print(f"[yellow]No open ports found on {target}[/yellow]")
            return
        
        table = Table(title=f"🔓 Open Ports on {target}")
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        
        for port_info in open_ports:
            table.add_row(
                str(port_info['port']),
                port_info['state'],
                port_info['service'],
                port_info['version']
            )
        
        self.console.print(table)
    
    async def _generate_port_report(self):
        """Generate port monitoring report"""
        if not self.port_history:
            return
        
        # Analyze port activity over time
        report = {
            'timestamp': datetime.now().isoformat(),
            'monitoring_duration': len(self.port_history),
            'total_snapshots': len(self.port_history),
            'port_activity_summary': self._analyze_port_activity(),
            'suspicious_activity': self._detect_suspicious_activity(),
            'listening_ports_summary': self._summarize_listening_ports()
        }
        
        await self.logger.save_report(report, "port_monitoring")
        self._display_port_summary(report)
    
    def _analyze_port_activity(self):
        """Analyze port activity patterns"""
        all_connections = []
        all_listening = []
        
        for snapshot in self.port_history.values():
            all_connections.extend(snapshot['connections'])
            all_listening.extend(snapshot['listening_ports'])
        
        # Count unique remote IPs
        remote_ips = set()
        local_ports = set()
        
        for conn in all_connections:
            if conn['remote_ip']:
                remote_ips.add(conn['remote_ip'])
            local_ports.add(conn['local_port'])
        
        return {
            'unique_remote_ips': len(remote_ips),
            'unique_local_ports': len(local_ports),
            'total_connections': len(all_connections),
            'listening_services': len(set(p['port'] for p in all_listening))
        }
    
    def _detect_suspicious_activity(self):
        """Detect suspicious port activity"""
        suspicious = []
        
        # Track connection patterns
        connection_counts = {}
        
        for snapshot in self.port_history.values():
            for conn in snapshot['connections']:
                if conn['remote_ip']:
                    key = conn['remote_ip']
                    connection_counts[key] = connection_counts.get(key, 0) + 1
        
        # Flag IPs with many connections
        for ip, count in connection_counts.items():
            if count > 50:  # Threshold for suspicious activity
                suspicious.append({
                    'type': 'high_connection_count',
                    'remote_ip': ip,
                    'connection_count': count,
                    'severity': 'medium'
                })
        
        return suspicious
    
    def _summarize_listening_ports(self):
        """Summarize listening ports across monitoring period"""
        all_listening = {}
        
        for snapshot in self.port_history.values():
            for port_info in snapshot['listening_ports']:
                port = port_info['port']
                if port not in all_listening:
                    all_listening[port] = {
                        'port': port,
                        'process_name': port_info['process_name'],
                        'first_seen': snapshot['timestamp'],
                        'count': 0
                    }
                all_listening[port]['count'] += 1
                all_listening[port]['last_seen'] = snapshot['timestamp']
        
        return list(all_listening.values())
    
    def _display_port_summary(self, report):
        """Display port monitoring summary"""
        self.console.print(Panel("📊 Port Monitoring Summary", style="bold blue"))
        
        summary = report['port_activity_summary']
        
        # Activity summary table
        activity_table = Table(title="Activity Summary")
        activity_table.add_column("Metric", style="cyan")
        activity_table.add_column("Value", style="yellow")
        
        activity_table.add_row("Total Connections", str(summary['total_connections']))
        activity_table.add_row("Unique Remote IPs", str(summary['unique_remote_ips']))
        activity_table.add_row("Unique Local Ports", str(summary['unique_local_ports']))
        activity_table.add_row("Listening Services", str(summary['listening_services']))
        
        self.console.print(activity_table)
        
        # Suspicious activity
        if report['suspicious_activity']:
            self.console.print(f"[red]⚠️ {len(report['suspicious_activity'])} suspicious activities detected![/red]")
            
            for activity in report['suspicious_activity']:
                self.console.print(f"  • {activity['type']}: {activity['remote_ip']} ({activity['connection_count']} connections)")
        
        # Top listening ports
        listening_summary = report['listening_ports_summary']
        if listening_summary:
            ports_table = Table(title="Persistent Listening Ports")
            ports_table.add_column("Port", style="cyan")
            ports_table.add_column("Process", style="yellow")
            ports_table.add_column("Occurrences", style="green")
            
            # Sort by occurrence count
            listening_summary.sort(key=lambda x: x['count'], reverse=True)
            
            for port_info in listening_summary[:10]:
                ports_table.add_row(
                    str(port_info['port']),
                    port_info['process_name'] or 'Unknown',
                    str(port_info['count'])
                )
            
            self.console.print(ports_table)