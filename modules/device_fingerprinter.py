#!/usr/bin/env python3
"""
Mauritania Eye - Device Fingerprinter Module
Network device identification and fingerprinting

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import subprocess
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class DeviceFingerprinter:
    """
    Device fingerprinting and identification module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.mac_vendors = {}  # Cache for MAC vendor lookups
        
    async def fingerprint_devices(self, hosts):
        """Fingerprint discovered network devices"""
        self.console.print(Panel("🖥️ Starting Device Fingerprinting", style="bold cyan"))
        
        fingerprinted_devices = []
        
        for host in hosts:
            device_info = await self._fingerprint_single_device(host)
            if device_info:
                fingerprinted_devices.append(device_info)
        
        # Display results
        self._display_fingerprinting_results(fingerprinted_devices)
        
        # Save report
        await self.logger.save_report({
            'timestamp': datetime.now().isoformat(),
            'total_devices': len(fingerprinted_devices),
            'device_fingerprints': fingerprinted_devices
        }, "device_fingerprinting")
        
        return fingerprinted_devices
    
    async def _fingerprint_single_device(self, host):
        """Fingerprint a single device"""
        device_info = {
            'ip': host.get('ip', ''),
            'hostname': host.get('hostname', ''),
            'mac_address': host.get('mac_address', ''),
            'vendor': host.get('vendor', ''),
            'timestamp': datetime.now().isoformat(),
            'device_type': 'Unknown',
            'os_family': 'Unknown',
            'os_details': {},
            'services': host.get('services', []),
            'open_ports': host.get('open_ports', []),
            'fingerprint_confidence': 0,
            'characteristics': []
        }
        
        # Enhanced MAC vendor lookup
        if device_info['mac_address']:
            vendor_info = await self._lookup_mac_vendor(device_info['mac_address'])
            if vendor_info:
                device_info['vendor'] = vendor_info
        
        # OS fingerprinting
        await self._fingerprint_os(device_info)
        
        # Device type detection
        await self._detect_device_type(device_info)
        
        # Service-based fingerprinting
        await self._analyze_services(device_info)
        
        # Calculate confidence score
        device_info['fingerprint_confidence'] = self._calculate_confidence(device_info)
        
        return device_info
    
    async def _lookup_mac_vendor(self, mac_address):
        """Enhanced MAC vendor lookup"""
        if not mac_address:
            return None
        
        # Extract OUI (first 3 octets)
        oui = mac_address.replace(':', '').replace('-', '').upper()[:6]
        
        if oui in self.mac_vendors:
            return self.mac_vendors[oui]
        
        vendor = None
        
        try:
            # Try using macchanger if available
            result = subprocess.run(
                ['macchanger', '-l'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if oui.lower() in line.lower():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            vendor = parts[1].strip()
                            break
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback: try online lookup
            vendor = await self._online_mac_lookup(oui)
        
        except Exception as e:
            self.logger.log_error("DeviceFingerprinter", f"MAC lookup error: {str(e)}")
        
        # Cache result
        if vendor:
            self.mac_vendors[oui] = vendor
        
        return vendor
    
    async def _online_mac_lookup(self, oui):
        """Online MAC vendor lookup as fallback"""
        try:
            result = subprocess.run(
                ['curl', '-s', f'https://api.macvendors.com/{oui}'],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                vendor = result.stdout.strip()
                if 'not found' not in vendor.lower():
                    return vendor
                    
        except Exception:
            pass
        
        return None
    
    async def _fingerprint_os(self, device_info):
        """Enhanced OS fingerprinting"""
        ip = device_info['ip']
        
        try:
            # Use nmap for OS detection
            result = subprocess.run(
                ['nmap', '-O', '-sS', '--osscan-guess', ip],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                os_info = self._parse_nmap_os_output(result.stdout)
                device_info['os_details'].update(os_info)
                
                # Determine OS family
                if os_info:
                    device_info['os_family'] = self._determine_os_family(os_info)
            
        except Exception as e:
            self.logger.log_error("DeviceFingerprinter", f"OS fingerprinting error for {ip}: {str(e)}")
        
        # Additional OS hints from services
        self._analyze_os_from_services(device_info)
    
    def _parse_nmap_os_output(self, nmap_output):
        """Parse nmap OS detection output"""
        os_info = {}
        
        lines = nmap_output.split('\n')
        in_os_section = False
        
        for line in lines:
            line = line.strip()
            
            if 'OS details:' in line:
                os_details = line.split('OS details:')[1].strip()
                os_info['details'] = os_details
            
            elif 'Running:' in line:
                running = line.split('Running:')[1].strip()
                os_info['running'] = running
            
            elif 'OS CPE:' in line:
                cpe = line.split('OS CPE:')[1].strip()
                os_info['cpe'] = cpe
            
            elif 'Aggressive OS guesses:' in line:
                in_os_section = True
                continue
            
            elif in_os_section and line and not line.startswith('No exact'):
                # Parse OS guess with confidence
                if '(' in line and ')' in line:
                    os_guess = line.split('(')[0].strip()
                    confidence_match = re.search(r'\((\d+)%\)', line)
                    confidence = int(confidence_match.group(1)) if confidence_match else 0
                    
                    if 'os_guesses' not in os_info:
                        os_info['os_guesses'] = []
                    
                    os_info['os_guesses'].append({
                        'os': os_guess,
                        'confidence': confidence
                    })
        
        return os_info
    
    def _determine_os_family(self, os_info):
        """Determine OS family from detection results"""
        # Check various fields for OS indicators
        text_to_check = ' '.join([
            os_info.get('details', ''),
            os_info.get('running', ''),
            os_info.get('cpe', '')
        ]).lower()
        
        # Add OS guesses
        if 'os_guesses' in os_info:
            for guess in os_info['os_guesses']:
                text_to_check += ' ' + guess['os'].lower()
        
        # OS family detection
        if any(keyword in text_to_check for keyword in ['windows', 'microsoft']):
            return 'Windows'
        elif any(keyword in text_to_check for keyword in ['linux', 'ubuntu', 'debian', 'centos', 'redhat']):
            return 'Linux'
        elif any(keyword in text_to_check for keyword in ['mac', 'darwin', 'osx']):
            return 'macOS'
        elif any(keyword in text_to_check for keyword in ['ios', 'iphone', 'ipad']):
            return 'iOS'
        elif any(keyword in text_to_check for keyword in ['android']):
            return 'Android'
        elif any(keyword in text_to_check for keyword in ['freebsd', 'openbsd', 'netbsd']):
            return 'BSD'
        elif any(keyword in text_to_check for keyword in ['solaris', 'sunos']):
            return 'Solaris'
        elif any(keyword in text_to_check for keyword in ['cisco', 'juniper', 'router', 'switch']):
            return 'Network Device'
        
        return 'Unknown'
    
    def _analyze_os_from_services(self, device_info):
        """Analyze OS hints from running services"""
        services = device_info.get('services', [])
        characteristics = []
        
        for service in services:
            service_name = service.get('service', '').lower()
            version = service.get('version', '').lower()
            product = service.get('product', '').lower()
            
            # Windows-specific services
            if any(svc in service_name for svc in ['microsoft', 'iis', 'rdp']):
                characteristics.append('Windows service detected')
                if device_info['os_family'] == 'Unknown':
                    device_info['os_family'] = 'Windows'
            
            # Linux-specific services
            elif any(svc in service_name for svc in ['apache', 'nginx', 'openssh']):
                characteristics.append('Unix-like service detected')
                if device_info['os_family'] == 'Unknown':
                    device_info['os_family'] = 'Linux'
            
            # Network device services
            elif any(svc in service_name for svc in ['snmp', 'telnet']) and service.get('port') in [161, 23]:
                characteristics.append('Network device service detected')
                if device_info['os_family'] == 'Unknown':
                    device_info['os_family'] = 'Network Device'
        
        device_info['characteristics'].extend(characteristics)
    
    async def _detect_device_type(self, device_info):
        """Detect device type based on various indicators"""
        # Check MAC vendor for device type hints
        vendor = device_info.get('vendor', '').lower()
        hostname = device_info.get('hostname', '').lower()
        os_family = device_info.get('os_family', '').lower()
        services = device_info.get('services', [])
        open_ports = device_info.get('open_ports', [])
        
        device_type = 'Unknown'
        confidence_factors = []
        
        # Router/Network equipment detection
        router_vendors = ['cisco', 'juniper', 'netgear', 'linksys', 'tp-link', 'asus', 'd-link']
        if any(rv in vendor for rv in router_vendors):
            device_type = 'Router/Network Device'
            confidence_factors.append('Router vendor detected')
        
        # Check for router-like hostnames
        router_hostnames = ['router', 'gateway', 'switch', 'ap', 'access-point']
        if any(rh in hostname for rh in router_hostnames):
            device_type = 'Router/Network Device'
            confidence_factors.append('Router hostname pattern')
        
        # Check for router services
        router_ports = [23, 80, 443, 161, 22]  # Telnet, HTTP, HTTPS, SNMP, SSH
        if len(set(open_ports) & set(router_ports)) >= 2:
            if device_type == 'Unknown':
                device_type = 'Router/Network Device'
            confidence_factors.append('Router service pattern')
        
        # Mobile device detection
        mobile_vendors = ['apple', 'samsung', 'huawei', 'xiaomi', 'lg', 'htc']
        if any(mv in vendor for mv in mobile_vendors) and os_family in ['ios', 'android']:
            device_type = 'Mobile Device'
            confidence_factors.append('Mobile vendor and OS')
        
        # Server detection
        server_services = ['ssh', 'http', 'https', 'ftp', 'smtp', 'dns']
        server_ports = [22, 80, 443, 21, 25, 53]
        
        if len(set(open_ports) & set(server_ports)) >= 3:
            device_type = 'Server'
            confidence_factors.append('Multiple server services')
        
        # Desktop/Workstation detection
        if os_family in ['windows', 'macos', 'linux'] and device_type == 'Unknown':
            if 3389 in open_ports:  # RDP
                device_type = 'Windows Desktop'
                confidence_factors.append('RDP service detected')
            elif 5900 in open_ports:  # VNC
                device_type = 'Desktop/Workstation'
                confidence_factors.append('VNC service detected')
            else:
                device_type = 'Desktop/Workstation'
                confidence_factors.append('Desktop OS detected')
        
        # IoT device detection
        iot_vendors = ['raspberry', 'arduino', 'espressif']
        if any(iot in vendor for iot in iot_vendors):
            device_type = 'IoT Device'
            confidence_factors.append('IoT vendor detected')
        
        # Printer detection
        printer_vendors = ['hp', 'canon', 'epson', 'brother', 'lexmark']
        if any(pv in vendor for pv in printer_vendors):
            device_type = 'Printer'
            confidence_factors.append('Printer vendor detected')
        
        # Check for printer services
        if 631 in open_ports or 9100 in open_ports:  # IPP, JetDirect
            device_type = 'Printer'
            confidence_factors.append('Printer service detected')
        
        device_info['device_type'] = device_type
        device_info['characteristics'].extend(confidence_factors)
    
    async def _analyze_services(self, device_info):
        """Analyze services for additional fingerprinting"""
        services = device_info.get('services', [])
        characteristics = device_info.get('characteristics', [])
        
        # Analyze service patterns
        web_services = [s for s in services if s.get('port') in [80, 443, 8080, 8443]]
        if web_services:
            characteristics.append(f'{len(web_services)} web service(s) detected')
        
        ssh_services = [s for s in services if s.get('service', '').lower() == 'ssh']
        if ssh_services:
            for ssh in ssh_services:
                version = ssh.get('version', '')
                if version:
                    characteristics.append(f'SSH version: {version}')
        
        # Database services
        db_ports = [3306, 5432, 1433, 1521, 27017]  # MySQL, PostgreSQL, SQL Server, Oracle, MongoDB
        db_services = [s for s in services if s.get('port') in db_ports]
        if db_services:
            characteristics.append('Database service detected')
        
        device_info['characteristics'] = characteristics
    
    def _calculate_confidence(self, device_info):
        """Calculate fingerprinting confidence score"""
        confidence = 0
        
        # Base confidence from OS detection
        if device_info['os_family'] != 'Unknown':
            confidence += 30
            
            # Bonus for detailed OS info
            if device_info.get('os_details'):
                confidence += 20
        
        # Confidence from device type detection
        if device_info['device_type'] != 'Unknown':
            confidence += 25
        
        # Confidence from vendor information
        if device_info.get('vendor') and device_info['vendor'] != 'Unknown':
            confidence += 15
        
        # Confidence from service analysis
        services_count = len(device_info.get('services', []))
        if services_count > 0:
            confidence += min(services_count * 2, 10)  # Max 10 points from services
        
        return min(confidence, 100)  # Cap at 100%
    
    def _display_fingerprinting_results(self, devices):
        """Display device fingerprinting results"""
        if not devices:
            self.console.print("[yellow]No devices to fingerprint[/yellow]")
            return
        
        # Summary table
        summary_table = Table(title=f"🖥️ Device Fingerprinting Results ({len(devices)} devices)")
        summary_table.add_column("IP Address", style="cyan")
        summary_table.add_column("Device Type", style="green")
        summary_table.add_column("OS Family", style="yellow")
        summary_table.add_column("Vendor", style="magenta")
        summary_table.add_column("Confidence", style="red")
        
        for device in devices:
            confidence_color = self._get_confidence_color(device['fingerprint_confidence'])
            summary_table.add_row(
                device['ip'],
                device['device_type'],
                device['os_family'],
                device['vendor'][:20] + "..." if len(device['vendor']) > 20 else device['vendor'],
                f"[{confidence_color}]{device['fingerprint_confidence']}%[/{confidence_color}]"
            )
        
        self.console.print(summary_table)
        
        # Device type distribution
        device_types = {}
        for device in devices:
            dtype = device['device_type']
            device_types[dtype] = device_types.get(dtype, 0) + 1
        
        if device_types:
            type_table = Table(title="Device Type Distribution")
            type_table.add_column("Device Type", style="cyan")
            type_table.add_column("Count", style="yellow")
            type_table.add_column("Percentage", style="green")
            
            total = len(devices)
            for dtype, count in sorted(device_types.items()):
                percentage = (count / total * 100) if total > 0 else 0
                type_table.add_row(dtype, str(count), f"{percentage:.1f}%")
            
            self.console.print(type_table)
        
        # High-confidence fingerprints
        high_confidence = [d for d in devices if d['fingerprint_confidence'] >= 70]
        if high_confidence:
            self.console.print(f"\n[green]✅ {len(high_confidence)} high-confidence fingerprints[/green]")
        
        # Low-confidence fingerprints
        low_confidence = [d for d in devices if d['fingerprint_confidence'] < 50]
        if low_confidence:
            self.console.print(f"[yellow]⚠️ {len(low_confidence)} low-confidence fingerprints may need manual verification[/yellow]")
    
    def _get_confidence_color(self, confidence):
        """Get color for confidence level"""
        if confidence >= 80:
            return 'bright_green'
        elif confidence >= 60:
            return 'green'
        elif confidence >= 40:
            return 'yellow'
        else:
            return 'red'
    
    async def interactive_fingerprint(self):
        """Interactive device fingerprinting mode"""
        self.console.print(Panel("🖥️ Interactive Device Fingerprinter", style="bold cyan"))
        
        ip = self.console.input("[yellow]Enter IP address to fingerprint: [/yellow]")
        if not ip:
            self.console.print("[red]No IP address provided[/red]")
            return
        
        # Create basic host info
        host_info = {'ip': ip}
        
        self.console.print(f"[cyan]Fingerprinting {ip}...[/cyan]")
        
        # Perform fingerprinting
        device_info = await self._fingerprint_single_device(host_info)
        
        if device_info:
            self._display_detailed_fingerprint(device_info)
        else:
            self.console.print("[red]Fingerprinting failed[/red]")
    
    def _display_detailed_fingerprint(self, device_info):
        """Display detailed fingerprint information for a single device"""
        self.console.print(Panel(f"🔍 Device Fingerprint: {device_info['ip']}", style="bold cyan"))
        
        # Basic info
        info_table = Table(show_header=False)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("IP Address", device_info['ip'])
        info_table.add_row("Hostname", device_info['hostname'] or 'Unknown')
        info_table.add_row("MAC Address", device_info['mac_address'] or 'Unknown')
        info_table.add_row("Vendor", device_info['vendor'] or 'Unknown')
        info_table.add_row("Device Type", device_info['device_type'])
        info_table.add_row("OS Family", device_info['os_family'])
        
        confidence_color = self._get_confidence_color(device_info['fingerprint_confidence'])
        info_table.add_row("Confidence", f"[{confidence_color}]{device_info['fingerprint_confidence']}%[/{confidence_color}]")
        
        self.console.print(info_table)
        
        # OS details
        if device_info['os_details']:
            os_table = Table(title="OS Detection Details")
            os_table.add_column("Field", style="cyan")
            os_table.add_column("Value", style="white")
            
            for field, value in device_info['os_details'].items():
                if field == 'os_guesses' and isinstance(value, list):
                    for i, guess in enumerate(value[:3]):  # Show top 3 guesses
                        os_table.add_row(f"OS Guess {i+1}", f"{guess['os']} ({guess['confidence']}%)")
                else:
                    os_table.add_row(field.replace('_', ' ').title(), str(value))
            
            self.console.print(os_table)
        
        # Characteristics
        if device_info['characteristics']:
            self.console.print("\n[bold]Fingerprinting Characteristics:[/bold]")
            for char in device_info['characteristics']:
                self.console.print(f"  • {char}")
        
        # Services
        if device_info['services']:
            services_table = Table(title="Detected Services")
            services_table.add_column("Port", style="yellow")
            services_table.add_column("Service", style="cyan")
            services_table.add_column("Product", style="green")
            services_table.add_column("Version", style="magenta")
            
            for service in device_info['services']:
                services_table.add_row(
                    str(service.get('port', '')),
                    service.get('service', ''),
                    service.get('product', ''),
                    service.get('version', '')
                )
            
            self.console.print(services_table)