#!/usr/bin/env python3
"""
Mauritania Eye - Network Scanner Module
Network discovery and port scanning capabilities

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import subprocess
import json
import ipaddress
from datetime import datetime
import nmap
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID
from rich.panel import Panel

class NetworkScanner:
    """
    Advanced network scanning and discovery module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.nm = nmap.PortScanner()
        
    async def discover_network(self, interface="eth0"):
        """Discover devices on the local network"""
        self.console.print(Panel("🔍 Starting Network Discovery", style="bold green"))
        
        # Get network range from interface
        network_range = await self._get_network_range(interface)
        if not network_range:
            self.console.print("[red]Could not determine network range[/red]")
            return []
        
        self.console.print(f"[cyan]Scanning network: {network_range}[/cyan]")
        
        # Perform network scan
        hosts = await self._scan_network_range(network_range)
        
        # Display results
        self._display_discovery_results(hosts)
        
        # Save results
        await self.logger.save_report({
            'timestamp': datetime.now().isoformat(),
            'network_range': network_range,
            'hosts_discovered': hosts
        }, "network_discovery")
        
        return hosts
    
    async def scan_target(self, target):
        """Scan specific target or network range"""
        self.console.print(Panel(f"🎯 Scanning Target: {target}", style="bold yellow"))
        
        try:
            # Validate target
            if '/' in target:
                # Network range
                network = ipaddress.ip_network(target, strict=False)
                hosts = await self._scan_network_range(str(network))
            else:
                # Single host
                hosts = await self._scan_single_host(target)
            
            self._display_scan_results(hosts, target)
            return hosts
            
        except Exception as e:
            self.console.print(f"[red]Error scanning target {target}: {str(e)}[/red]")
            return []
    
    async def _get_network_range(self, interface):
        """Get network range from interface"""
        try:
            # Use ip command to get interface info
            result = subprocess.run(
                ['ip', 'route', 'show', 'dev', interface],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'scope link' in line:
                        parts = line.split()
                        if len(parts) > 0 and '/' in parts[0]:
                            return parts[0]
            
            # Fallback: try to get from ip addr
            result = subprocess.run(
                ['ip', 'addr', 'show', interface],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line and 'scope global' in line:
                        parts = line.strip().split()
                        for part in parts:
                            if '/' in part and not part.startswith('inet'):
                                ip_net = ipaddress.ip_network(part, strict=False)
                                return str(ip_net)
            
        except Exception as e:
            self.logger.log_error("NetworkScanner", f"Error getting network range: {str(e)}")
        
        return None
    
    async def _scan_network_range(self, network_range):
        """Scan a network range for active hosts"""
        hosts = []
        
        try:
            with Progress() as progress:
                task = progress.add_task("Scanning network...", total=100)
                
                # Use nmap for host discovery
                self.nm.scan(hosts=network_range, arguments='-sn -T4')
                
                progress.update(task, completed=50)
                
                # Process results
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        host_info = await self._get_host_details(host)
                        hosts.append(host_info)
                
                progress.update(task, completed=100)
                
        except Exception as e:
            self.logger.log_error("NetworkScanner", f"Network scan error: {str(e)}")
        
        return hosts
    
    async def _scan_single_host(self, host):
        """Perform detailed scan of a single host"""
        hosts = []
        
        try:
            # Check if host is up
            self.nm.scan(hosts=host, arguments='-sn')
            
            if host in self.nm.all_hosts() and self.nm[host].state() == 'up':
                host_info = await self._get_host_details(host, detailed=True)
                hosts.append(host_info)
            
        except Exception as e:
            self.logger.log_error("NetworkScanner", f"Host scan error: {str(e)}")
        
        return hosts
    
    async def _get_host_details(self, host, detailed=False):
        """Get detailed information about a host"""
        host_info = {
            'ip': host,
            'status': 'up',
            'timestamp': datetime.now().isoformat(),
            'hostname': '',
            'mac_address': '',
            'vendor': '',
            'open_ports': [],
            'os_info': {},
            'services': []
        }
        
        try:
            # Get hostname
            if 'hostnames' in self.nm[host]:
                hostnames = self.nm[host]['hostnames']
                if hostnames:
                    host_info['hostname'] = hostnames[0]['name']
            
            # Get MAC address and vendor
            if 'addresses' in self.nm[host]:
                addresses = self.nm[host]['addresses']
                if 'mac' in addresses:
                    host_info['mac_address'] = addresses['mac']
                    # Get vendor info
                    host_info['vendor'] = self.nm[host]['vendor'].get(addresses['mac'], '')
            
            # Detailed scan for ports and services
            if detailed:
                await self._scan_host_ports(host, host_info)
                await self._detect_os(host, host_info)
            
        except Exception as e:
            self.logger.log_error("NetworkScanner", f"Error getting host details for {host}: {str(e)}")
        
        return host_info
    
    async def _scan_host_ports(self, host, host_info):
        """Scan ports on a specific host"""
        try:
            # Scan common ports
            self.nm.scan(host, '22,23,25,53,80,110,443,993,995,1723,3389,5900,8080')
            
            if host in self.nm.all_hosts():
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        if port_info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'protocol': protocol,
                                'state': port_info['state'],
                                'service': port_info.get('name', ''),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            }
                            host_info['open_ports'].append(port)
                            host_info['services'].append(service_info)
            
        except Exception as e:
            self.logger.log_error("NetworkScanner", f"Port scan error for {host}: {str(e)}")
    
    async def _detect_os(self, host, host_info):
        """Attempt OS detection"""
        try:
            self.nm.scan(host, arguments='-O')
            
            if host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    os_matches = self.nm[host]['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        host_info['os_info'] = {
                            'name': best_match.get('name', ''),
                            'accuracy': best_match.get('accuracy', ''),
                            'line': best_match.get('line', '')
                        }
            
        except Exception as e:
            self.logger.log_error("NetworkScanner", f"OS detection error for {host}: {str(e)}")
    
    def _display_discovery_results(self, hosts):
        """Display network discovery results"""
        if not hosts:
            self.console.print("[yellow]No hosts discovered[/yellow]")
            return
        
        table = Table(title=f"🌐 Network Discovery Results ({len(hosts)} hosts)")
        table.add_column("IP Address", style="cyan")
        table.add_column("Hostname", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Vendor", style="magenta")
        
        for host in hosts:
            table.add_row(
                host['ip'],
                host['hostname'] or 'Unknown',
                host['mac_address'] or 'Unknown',
                host['vendor'] or 'Unknown'
            )
        
        self.console.print(table)
    
    def _display_scan_results(self, hosts, target):
        """Display detailed scan results"""
        if not hosts:
            self.console.print(f"[yellow]No active hosts found for {target}[/yellow]")
            return
        
        for host in hosts:
            self.console.print(Panel(f"🖥️ Host: {host['ip']}", style="bold cyan"))
            
            # Basic info table
            info_table = Table(show_header=False)
            info_table.add_column("Property", style="cyan")
            info_table.add_column("Value", style="white")
            
            info_table.add_row("Hostname", host['hostname'] or 'Unknown')
            info_table.add_row("MAC Address", host['mac_address'] or 'Unknown')
            info_table.add_row("Vendor", host['vendor'] or 'Unknown')
            
            if host['os_info']:
                info_table.add_row("OS", f"{host['os_info']['name']} ({host['os_info']['accuracy']}% confidence)")
            
            self.console.print(info_table)
            
            # Open ports
            if host['open_ports']:
                ports_table = Table(title="Open Ports")
                ports_table.add_column("Port", style="yellow")
                ports_table.add_column("Protocol", style="green")
                ports_table.add_column("Service", style="cyan")
                ports_table.add_column("Version", style="magenta")
                
                for service in host['services']:
                    ports_table.add_row(
                        str(service['port']),
                        service['protocol'],
                        service['service'],
                        f"{service['product']} {service['version']}".strip()
                    )
                
                self.console.print(ports_table)
            
            self.console.print()  # Empty line between hosts
    
    async def interactive_scan(self):
        """Interactive scanning mode"""
        self.console.print(Panel("🎯 Interactive Network Scanner", style="bold blue"))
        
        scan_type = self.console.input(
            "[cyan]Select scan type:\n"
            "1. Network Discovery\n"
            "2. Target Scan\n"
            "3. Port Scan\n"
            "Choice (1-3): [/cyan]"
        )
        
        if scan_type == "1":
            interface = self.console.input("[yellow]Network interface (default: eth0): [/yellow]") or "eth0"
            await self.discover_network(interface)
        
        elif scan_type == "2":
            target = self.console.input("[yellow]Target IP or network (e.g., 192.168.1.1 or 192.168.1.0/24): [/yellow]")
            if target:
                await self.scan_target(target)
        
        elif scan_type == "3":
            host = self.console.input("[yellow]Host to scan: [/yellow]")
            if host:
                await self._scan_single_host(host)
        
        else:
            self.console.print("[red]Invalid choice[/red]")