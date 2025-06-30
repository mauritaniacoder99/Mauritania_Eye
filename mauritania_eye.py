#!/usr/bin/env python3
"""
Mauritania Eye - Advanced Network Intelligence Framework
Professional Command-Line Network Monitoring and Analysis Tool

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
Version: 3.0.0
Target: Kali Linux Terminal Environment

A unified cybersecurity intelligence platform for network monitoring,
vulnerability assessment, and threat analysis.
"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.layout import Layout
from rich.live import Live
import signal

# Import custom modules
from modules.packet_sniffer import PacketSniffer
from modules.network_scanner import NetworkScanner
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.port_monitor import PortMonitor
from modules.spoofing_detector import SpoofingDetector
from modules.geoip_analyzer import GeoIPAnalyzer
from modules.device_fingerprinter import DeviceFingerprinter
from modules.system_monitor import SystemMonitor
from modules.logger import MauritaniaLogger
from modules.config_manager import ConfigManager

console = Console()

class MauritaniaEye:
    """
    Main controller class for Mauritania Eye Network Intelligence Framework
    """
    
    def __init__(self):
        self.console = Console()
        self.config = ConfigManager()
        self.logger = MauritaniaLogger()
        self.running = False
        
        # Initialize modules
        self.packet_sniffer = PacketSniffer(self.logger)
        self.network_scanner = NetworkScanner(self.logger)
        self.vuln_scanner = VulnerabilityScanner(self.logger)
        self.port_monitor = PortMonitor(self.logger)
        self.spoofing_detector = SpoofingDetector(self.logger)
        self.geoip_analyzer = GeoIPAnalyzer(self.logger)
        self.device_fingerprinter = DeviceFingerprinter(self.logger)
        self.system_monitor = SystemMonitor(self.logger)
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.console.print("\n[yellow]Shutting down Mauritania Eye...[/yellow]")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Cleanup resources and save final reports"""
        self.logger.save_session_report()
        self.console.print("[green]Session saved successfully[/green]")
    
    def display_banner(self):
        """Display the Mauritania Eye banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    🌐🧿 MAURITANIA EYE - HYPERVISION MODE                    ║
║                   Advanced Network Intelligence Framework                    ║
║                                                                              ║
║                    Author: Mohamed Lemine Ahmed Jidou 🇲🇷                    ║
║                              Version: 3.0.0                                 ║
║                         Target: Kali Linux Terminal                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        self.console.print(Panel(banner, style="bold blue"))
    
    def display_main_menu(self):
        """Display the main menu options"""
        table = Table(title="🔍 Available Modules", show_header=True, header_style="bold magenta")
        table.add_column("Module", style="cyan", width=20)
        table.add_column("Description", style="white", width=50)
        table.add_column("Status", style="green", width=10)
        
        modules = [
            ("Packet Sniffer", "Real-time network traffic analysis", "✅ Ready"),
            ("Network Scanner", "Network discovery and port scanning", "✅ Ready"),
            ("Vulnerability Scanner", "Web application security assessment", "✅ Ready"),
            ("Port Monitor", "Active port and service monitoring", "✅ Ready"),
            ("Spoofing Detector", "ARP and DNS spoofing detection", "✅ Ready"),
            ("GeoIP Analyzer", "Geographic IP analysis and tracking", "✅ Ready"),
            ("Device Fingerprinter", "Network device identification", "✅ Ready"),
            ("System Monitor", "Real-time system resource monitoring", "✅ Ready"),
        ]
        
        for module, description, status in modules:
            table.add_row(module, description, status)
        
        self.console.print(table)
    
    async def run_auto_mode(self, target=None, interface="eth0"):
        """Run automated comprehensive scan"""
        self.console.print(Panel("[bold green]🚀 Starting Automated Intelligence Gathering[/bold green]"))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Phase 1: Network Discovery
            task1 = progress.add_task("🔍 Network Discovery...", total=100)
            if target:
                network_results = await self.network_scanner.scan_target(target)
            else:
                network_results = await self.network_scanner.discover_network(interface)
            progress.update(task1, completed=100)
            
            # Phase 2: Device Fingerprinting
            task2 = progress.add_task("🖥️ Device Fingerprinting...", total=100)
            device_results = await self.device_fingerprinter.fingerprint_devices(network_results)
            progress.update(task2, completed=100)
            
            # Phase 3: Vulnerability Assessment
            task3 = progress.add_task("🛡️ Vulnerability Assessment...", total=100)
            vuln_results = await self.vuln_scanner.scan_targets(network_results)
            progress.update(task3, completed=100)
            
            # Phase 4: GeoIP Analysis
            task4 = progress.add_task("🌍 GeoIP Analysis...", total=100)
            geo_results = await self.geoip_analyzer.analyze_ips(network_results)
            progress.update(task4, completed=100)
            
            # Phase 5: Generate Report
            task5 = progress.add_task("📊 Generating Report...", total=100)
            await self.generate_comprehensive_report({
                'network': network_results,
                'devices': device_results,
                'vulnerabilities': vuln_results,
                'geoip': geo_results
            })
            progress.update(task5, completed=100)
        
        self.console.print("[bold green]✅ Automated scan completed successfully![/bold green]")
    
    async def run_manual_mode(self):
        """Run interactive manual mode"""
        while self.running:
            self.console.print("\n" + "="*80)
            self.console.print("[bold cyan]🔧 Manual Mode - Select Module:[/bold cyan]")
            
            options = [
                ("1", "Packet Sniffer", self.packet_sniffer.start_sniffing),
                ("2", "Network Scanner", self.network_scanner.interactive_scan),
                ("3", "Vulnerability Scanner", self.vuln_scanner.interactive_scan),
                ("4", "Port Monitor", self.port_monitor.monitor_ports),
                ("5", "Spoofing Detector", self.spoofing_detector.start_detection),
                ("6", "GeoIP Analyzer", self.geoip_analyzer.interactive_lookup),
                ("7", "Device Fingerprinter", self.device_fingerprinter.interactive_fingerprint),
                ("8", "System Monitor", self.system_monitor.start_monitoring),
                ("9", "View Logs", self.view_logs),
                ("0", "Exit", self.exit_program)
            ]
            
            for num, name, _ in options:
                self.console.print(f"[cyan]{num}[/cyan]. {name}")
            
            choice = self.console.input("\n[bold yellow]Select option (0-9): [/bold yellow]")
            
            for num, name, func in options:
                if choice == num:
                    if choice == "0":
                        func()
                        return
                    else:
                        await func()
                    break
            else:
                self.console.print("[red]Invalid option. Please try again.[/red]")
    
    async def generate_comprehensive_report(self, results):
        """Generate comprehensive analysis report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_data = {
            'timestamp': timestamp,
            'scan_type': 'comprehensive',
            'results': results,
            'summary': {
                'total_hosts': len(results.get('network', [])),
                'vulnerabilities_found': len(results.get('vulnerabilities', [])),
                'devices_fingerprinted': len(results.get('devices', [])),
                'geoip_analyzed': len(results.get('geoip', []))
            }
        }
        
        # Save JSON report
        await self.logger.save_report(report_data, f"comprehensive_report_{timestamp}")
        
        # Display summary
        self.display_report_summary(report_data)
    
    def display_report_summary(self, report_data):
        """Display report summary in terminal"""
        summary = report_data['summary']
        
        table = Table(title="📊 Scan Summary", show_header=True, header_style="bold green")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="yellow")
        
        table.add_row("Total Hosts Discovered", str(summary['total_hosts']))
        table.add_row("Vulnerabilities Found", str(summary['vulnerabilities_found']))
        table.add_row("Devices Fingerprinted", str(summary['devices_fingerprinted']))
        table.add_row("IPs Analyzed (GeoIP)", str(summary['geoip_analyzed']))
        
        self.console.print(table)
    
    def view_logs(self):
        """Display recent logs"""
        logs = self.logger.get_recent_logs(50)
        
        table = Table(title="📋 Recent Activity Logs", show_header=True, header_style="bold blue")
        table.add_column("Timestamp", style="cyan", width=20)
        table.add_column("Module", style="green", width=15)
        table.add_column("Level", style="yellow", width=10)
        table.add_column("Message", style="white", width=50)
        
        for log in logs:
            table.add_row(
                log.get('timestamp', ''),
                log.get('module', ''),
                log.get('level', ''),
                log.get('message', '')
            )
        
        self.console.print(table)
    
    def exit_program(self):
        """Exit the program gracefully"""
        self.running = False
        self.cleanup()

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Mauritania Eye - Advanced Network Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mauritania_eye.py --auto                    # Full automated scan
  python3 mauritania_eye.py --auto --target 192.168.1.0/24  # Scan specific network
  python3 mauritania_eye.py --manual                  # Interactive mode
  python3 mauritania_eye.py --interface wlan0         # Use specific interface
        """
    )
    
    parser.add_argument('--auto', action='store_true', 
                       help='Run automated comprehensive scan')
    parser.add_argument('--manual', action='store_true', 
                       help='Run interactive manual mode')
    parser.add_argument('--target', type=str, 
                       help='Target network or IP (e.g., 192.168.1.0/24)')
    parser.add_argument('--interface', type=str, default='eth0',
                       help='Network interface to use (default: eth0)')
    parser.add_argument('--config', type=str, default='config.json',
                       help='Configuration file path')
    parser.add_argument('--output', type=str, default='logs',
                       help='Output directory for logs and reports')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Initialize Mauritania Eye
    eye = MauritaniaEye()
    eye.running = True
    
    # Display banner
    eye.display_banner()
    
    # Load configuration
    if os.path.exists(args.config):
        eye.config.load_config(args.config)
    
    # Set output directory
    eye.logger.set_output_dir(args.output)
    
    try:
        if args.auto:
            await eye.run_auto_mode(args.target, args.interface)
        elif args.manual:
            await eye.run_manual_mode()
        else:
            # Default: show menu and run manual mode
            eye.display_main_menu()
            console.print("\n[yellow]No mode specified. Starting manual mode...[/yellow]")
            await eye.run_manual_mode()
    
    except KeyboardInterrupt:
        eye.signal_handler(signal.SIGINT, None)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        if args.verbose:
            console.print_exception()
    finally:
        eye.cleanup()

if __name__ == "__main__":
    # Ensure we're running on Python 3.7+
    if sys.version_info < (3, 7):
        print("Error: Mauritania Eye requires Python 3.7 or higher")
        sys.exit(1)
    
    # Check if running as root (required for packet sniffing)
    if os.geteuid() != 0:
        print("Warning: Some features require root privileges")
        print("Run with sudo for full functionality")
    
    # Run the main program
    asyncio.run(main())