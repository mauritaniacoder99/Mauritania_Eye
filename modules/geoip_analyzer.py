#!/usr/bin/env python3
"""
Mauritania Eye - GeoIP Analyzer Module
Geographic IP analysis and threat intelligence

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import subprocess
import json
import re
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

class GeoIPAnalyzer:
    """
    Geographic IP analysis and WHOIS lookup module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.ip_cache = {}  # Cache for IP lookups
        
    async def analyze_ips(self, hosts):
        """Analyze geographic information for discovered hosts"""
        self.console.print(Panel("🌍 Starting GeoIP Analysis", style="bold blue"))
        
        results = []
        
        for host in hosts:
            ip = host.get('ip', '')
            if ip and not self._is_private_ip(ip):
                geo_info = await self._analyze_single_ip(ip)
                if geo_info:
                    geo_info['host_info'] = host
                    results.append(geo_info)
        
        # Display results
        self._display_geoip_results(results)
        
        # Save report
        await self.logger.save_report({
            'timestamp': datetime.now().isoformat(),
            'analyzed_ips': len(results),
            'geoip_data': results
        }, "geoip_analysis")
        
        return results
    
    async def _analyze_single_ip(self, ip):
        """Analyze a single IP address"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        geo_info = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'country': 'Unknown',
            'city': 'Unknown',
            'region': 'Unknown',
            'isp': 'Unknown',
            'organization': 'Unknown',
            'asn': 'Unknown',
            'threat_level': 'Unknown',
            'whois_data': {}
        }
        
        # Get GeoIP information
        await self._get_geoip_info(ip, geo_info)
        
        # Get WHOIS information
        await self._get_whois_info(ip, geo_info)
        
        # Assess threat level
        geo_info['threat_level'] = self._assess_threat_level(geo_info)
        
        # Cache result
        self.ip_cache[ip] = geo_info
        
        return geo_info
    
    async def _get_geoip_info(self, ip, geo_info):
        """Get geographic information for IP"""
        try:
            # Try using geoiplookup if available
            result = subprocess.run(
                ['geoiplookup', ip],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                
                # Parse geoiplookup output
                if 'GeoIP Country Edition:' in output:
                    country_line = [line for line in output.split('\n') if 'GeoIP Country Edition:' in line]
                    if country_line:
                        country_info = country_line[0].split('GeoIP Country Edition:')[1].strip()
                        if ',' in country_info:
                            parts = country_info.split(',')
                            geo_info['country'] = parts[1].strip() if len(parts) > 1 else country_info
                
                if 'GeoIP City Edition:' in output:
                    city_line = [line for line in output.split('\n') if 'GeoIP City Edition:' in line]
                    if city_line:
                        city_info = city_line[0].split('GeoIP City Edition:')[1].strip()
                        parts = city_info.split(',')
                        if len(parts) >= 2:
                            geo_info['city'] = parts[0].strip()
                            geo_info['region'] = parts[1].strip()
            
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback: try using curl with ip-api.com
            await self._get_geoip_from_api(ip, geo_info)
        except Exception as e:
            self.logger.log_error("GeoIPAnalyzer", f"GeoIP lookup error for {ip}: {str(e)}")
    
    async def _get_geoip_from_api(self, ip, geo_info):
        """Get GeoIP info from online API as fallback"""
        try:
            result = subprocess.run(
                ['curl', '-s', f'http://ip-api.com/json/{ip}'],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    if data.get('status') == 'success':
                        geo_info['country'] = data.get('country', 'Unknown')
                        geo_info['city'] = data.get('city', 'Unknown')
                        geo_info['region'] = data.get('regionName', 'Unknown')
                        geo_info['isp'] = data.get('isp', 'Unknown')
                        geo_info['organization'] = data.get('org', 'Unknown')
                        geo_info['asn'] = data.get('as', 'Unknown')
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            self.logger.log_error("GeoIPAnalyzer", f"API GeoIP lookup error for {ip}: {str(e)}")
    
    async def _get_whois_info(self, ip, geo_info):
        """Get WHOIS information for IP"""
        try:
            result = subprocess.run(
                ['whois', ip],
                capture_output=True, text=True, timeout=20
            )
            
            if result.returncode == 0:
                whois_output = result.stdout
                
                # Parse WHOIS data
                whois_data = self._parse_whois_output(whois_output)
                geo_info['whois_data'] = whois_data
                
                # Extract additional info from WHOIS
                if 'org' in whois_data and geo_info['organization'] == 'Unknown':
                    geo_info['organization'] = whois_data['org']
                
                if 'country' in whois_data and geo_info['country'] == 'Unknown':
                    geo_info['country'] = whois_data['country']
                    
        except Exception as e:
            self.logger.log_error("GeoIPAnalyzer", f"WHOIS lookup error for {ip}: {str(e)}")
    
    def _parse_whois_output(self, whois_output):
        """Parse WHOIS output into structured data"""
        whois_data = {}
        
        # Common WHOIS fields to extract
        fields = {
            'org': ['org:', 'organization:', 'orgname:'],
            'country': ['country:', 'country-code:'],
            'netname': ['netname:', 'net-name:'],
            'descr': ['descr:', 'description:'],
            'admin_contact': ['admin-c:', 'admin-contact:'],
            'tech_contact': ['tech-c:', 'tech-contact:'],
            'created': ['created:', 'creation-date:'],
            'updated': ['updated:', 'last-modified:']
        }
        
        lines = whois_output.lower().split('\n')
        
        for field, patterns in fields.items():
            for line in lines:
                for pattern in patterns:
                    if line.strip().startswith(pattern):
                        value = line.split(pattern, 1)[1].strip()
                        if value and value not in ['', '-', 'n/a']:
                            whois_data[field] = value
                        break
                if field in whois_data:
                    break
        
        return whois_data
    
    def _assess_threat_level(self, geo_info):
        """Assess threat level based on geographic and organizational data"""
        threat_score = 0
        
        # Country-based assessment
        high_risk_countries = [
            'china', 'russia', 'north korea', 'iran'
        ]
        
        medium_risk_countries = [
            'ukraine', 'romania', 'brazil', 'india'
        ]
        
        country = geo_info['country'].lower()
        if any(risk_country in country for risk_country in high_risk_countries):
            threat_score += 3
        elif any(risk_country in country for risk_country in medium_risk_countries):
            threat_score += 2
        
        # Organization-based assessment
        suspicious_orgs = [
            'hosting', 'vpn', 'proxy', 'tor', 'anonymous'
        ]
        
        org = geo_info['organization'].lower()
        if any(sus_org in org for sus_org in suspicious_orgs):
            threat_score += 2
        
        # ISP-based assessment
        isp = geo_info['isp'].lower()
        if any(sus_org in isp for sus_org in suspicious_orgs):
            threat_score += 1
        
        # Determine threat level
        if threat_score >= 4:
            return 'High'
        elif threat_score >= 2:
            return 'Medium'
        elif threat_score >= 1:
            return 'Low'
        else:
            return 'Minimal'
    
    def _is_private_ip(self, ip):
        """Check if IP is in private address space"""
        private_ranges = [
            '127.',      # Loopback
            '10.',       # Private Class A
            '192.168.',  # Private Class C
            '169.254.',  # Link-local
            '224.',      # Multicast
            '255.'       # Broadcast
        ]
        
        # Private Class B (172.16.0.0 - 172.31.255.255)
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def _display_geoip_results(self, results):
        """Display GeoIP analysis results"""
        if not results:
            self.console.print("[yellow]No external IPs to analyze[/yellow]")
            return
        
        # Summary table
        summary_table = Table(title=f"🌍 GeoIP Analysis Results ({len(results)} IPs)")
        summary_table.add_column("IP Address", style="cyan")
        summary_table.add_column("Country", style="green")
        summary_table.add_column("City", style="yellow")
        summary_table.add_column("Organization", style="magenta")
        summary_table.add_column("Threat Level", style="red")
        
        for result in results:
            threat_color = self._get_threat_color(result['threat_level'])
            summary_table.add_row(
                result['ip'],
                result['country'],
                result['city'],
                result['organization'][:30] + "..." if len(result['organization']) > 30 else result['organization'],
                f"[{threat_color}]{result['threat_level']}[/{threat_color}]"
            )
        
        self.console.print(summary_table)
        
        # Threat level distribution
        threat_counts = {}
        for result in results:
            level = result['threat_level']
            threat_counts[level] = threat_counts.get(level, 0) + 1
        
        if threat_counts:
            threat_table = Table(title="Threat Level Distribution")
            threat_table.add_column("Threat Level", style="cyan")
            threat_table.add_column("Count", style="yellow")
            threat_table.add_column("Percentage", style="green")
            
            total = len(results)
            for level, count in sorted(threat_counts.items()):
                percentage = (count / total * 100) if total > 0 else 0
                color = self._get_threat_color(level)
                threat_table.add_row(
                    f"[{color}]{level}[/{color}]",
                    str(count),
                    f"{percentage:.1f}%"
                )
            
            self.console.print(threat_table)
        
        # High-risk IPs
        high_risk_ips = [r for r in results if r['threat_level'] in ['High', 'Medium']]
        if high_risk_ips:
            self.console.print(f"\n[red]⚠️ {len(high_risk_ips)} potentially risky IPs detected![/red]")
            
            for ip_info in high_risk_ips[:5]:  # Show top 5
                self.console.print(f"  • {ip_info['ip']} ({ip_info['country']}) - {ip_info['organization']}")
    
    def _get_threat_color(self, threat_level):
        """Get color for threat level"""
        colors = {
            'High': 'bright_red',
            'Medium': 'red',
            'Low': 'yellow',
            'Minimal': 'green',
            'Unknown': 'white'
        }
        return colors.get(threat_level, 'white')
    
    async def interactive_lookup(self):
        """Interactive IP lookup mode"""
        self.console.print(Panel("🌍 Interactive GeoIP Lookup", style="bold blue"))
        
        while True:
            ip = self.console.input("[yellow]Enter IP address (or 'quit' to exit): [/yellow]")
            
            if ip.lower() in ['quit', 'exit', 'q']:
                break
            
            if not ip:
                continue
            
            # Validate IP format
            if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
                self.console.print("[red]Invalid IP address format[/red]")
                continue
            
            # Perform lookup
            self.console.print(f"[cyan]Looking up {ip}...[/cyan]")
            geo_info = await self._analyze_single_ip(ip)
            
            if geo_info:
                self._display_single_ip_info(geo_info)
            else:
                self.console.print("[red]Lookup failed[/red]")
    
    def _display_single_ip_info(self, geo_info):
        """Display detailed information for a single IP"""
        self.console.print(Panel(f"📍 IP Information: {geo_info['ip']}", style="bold cyan"))
        
        # Basic info table
        info_table = Table(show_header=False)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="white")
        
        info_table.add_row("Country", geo_info['country'])
        info_table.add_row("City", geo_info['city'])
        info_table.add_row("Region", geo_info['region'])
        info_table.add_row("ISP", geo_info['isp'])
        info_table.add_row("Organization", geo_info['organization'])
        info_table.add_row("ASN", geo_info['asn'])
        
        threat_color = self._get_threat_color(geo_info['threat_level'])
        info_table.add_row("Threat Level", f"[{threat_color}]{geo_info['threat_level']}[/{threat_color}]")
        
        self.console.print(info_table)
        
        # WHOIS data
        if geo_info['whois_data']:
            whois_table = Table(title="WHOIS Information")
            whois_table.add_column("Field", style="cyan")
            whois_table.add_column("Value", style="white")
            
            for field, value in geo_info['whois_data'].items():
                whois_table.add_row(field.replace('_', ' ').title(), str(value))
            
            self.console.print(whois_table)
        
        self.console.print()  # Empty line