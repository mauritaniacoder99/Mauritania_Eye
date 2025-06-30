#!/usr/bin/env python3
"""
Mauritania Eye - Logger Module
Centralized logging and reporting system

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path
import asyncio

class MauritaniaLogger:
    """
    Centralized logging and reporting system
    """
    
    def __init__(self, output_dir="logs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "reports").mkdir(exist_ok=True)
        (self.output_dir / "packets").mkdir(exist_ok=True)
        (self.output_dir / "alerts").mkdir(exist_ok=True)
        (self.output_dir / "sessions").mkdir(exist_ok=True)
        
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_logs = []
        
    def set_output_dir(self, output_dir):
        """Set custom output directory"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "reports").mkdir(exist_ok=True)
        (self.output_dir / "packets").mkdir(exist_ok=True)
        (self.output_dir / "alerts").mkdir(exist_ok=True)
        (self.output_dir / "sessions").mkdir(exist_ok=True)
    
    def log_info(self, module, message):
        """Log informational message"""
        self._log_message("INFO", module, message)
    
    def log_warning(self, module, message):
        """Log warning message"""
        self._log_message("WARNING", module, message)
    
    def log_error(self, module, message):
        """Log error message"""
        self._log_message("ERROR", module, message)
    
    def _log_message(self, level, module, message):
        """Internal logging method"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'module': module,
            'message': message
        }
        
        self.session_logs.append(log_entry)
        
        # Also write to daily log file
        log_file = self.output_dir / f"mauritania_eye_{datetime.now().strftime('%Y%m%d')}.log"
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"{log_entry['timestamp']} [{level}] {module}: {message}\n")
    
    def log_packet(self, packet_info):
        """Log packet information"""
        timestamp = datetime.now().strftime("%Y%m%d_%H")
        packet_file = self.output_dir / "packets" / f"packets_{timestamp}.json"
        
        # Append to hourly packet file
        with open(packet_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(packet_info) + '\n')
    
    def log_alert(self, module, alert_info):
        """Log security alert"""
        alert_entry = {
            'timestamp': datetime.now().isoformat(),
            'module': module,
            'alert': alert_info
        }
        
        # Write to alerts file
        alert_file = self.output_dir / "alerts" / f"alerts_{datetime.now().strftime('%Y%m%d')}.json"
        
        with open(alert_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(alert_entry) + '\n')
        
        # Also log as warning
        self.log_warning(module, f"Alert: {alert_info.get('type', 'Unknown')}")
    
    async def log_port_activity(self, port_state):
        """Log port monitoring activity"""
        port_file = self.output_dir / f"port_activity_{datetime.now().strftime('%Y%m%d')}.json"
        
        with open(port_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(port_state) + '\n')
    
    async def save_report(self, report_data, report_type):
        """Save comprehensive report in multiple formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{report_type}_{timestamp}"
        
        # Save as JSON
        json_file = self.output_dir / "reports" / f"{base_filename}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        # Save as CSV (if data is suitable)
        await self._save_report_csv(report_data, report_type, base_filename)
        
        self.log_info("Logger", f"Report saved: {base_filename}")
    
    async def _save_report_csv(self, report_data, report_type, base_filename):
        """Save report data as CSV"""
        csv_file = self.output_dir / "reports" / f"{base_filename}.csv"
        
        try:
            # Handle different report types
            if report_type == "network_discovery" and 'hosts_discovered' in report_data:
                await self._save_hosts_csv(report_data['hosts_discovered'], csv_file)
            
            elif report_type == "vulnerability_assessment" and 'vulnerabilities' in report_data:
                await self._save_vulnerabilities_csv(report_data['vulnerabilities'], csv_file)
            
            elif report_type == "geoip_analysis" and 'geoip_data' in report_data:
                await self._save_geoip_csv(report_data['geoip_data'], csv_file)
            
            elif report_type == "packet_analysis" and 'recent_packets' in report_data:
                await self._save_packets_csv(report_data['recent_packets'], csv_file)
            
        except Exception as e:
            self.log_error("Logger", f"Error saving CSV report: {str(e)}")
    
    async def _save_hosts_csv(self, hosts, csv_file):
        """Save hosts data as CSV"""
        if not hosts:
            return
        
        fieldnames = ['ip', 'hostname', 'mac_address', 'vendor', 'os_info', 'open_ports']
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for host in hosts:
                row = {
                    'ip': host.get('ip', ''),
                    'hostname': host.get('hostname', ''),
                    'mac_address': host.get('mac_address', ''),
                    'vendor': host.get('vendor', ''),
                    'os_info': str(host.get('os_info', {})),
                    'open_ports': ','.join(map(str, host.get('open_ports', [])))
                }
                writer.writerow(row)
    
    async def _save_vulnerabilities_csv(self, vulnerabilities, csv_file):
        """Save vulnerabilities data as CSV"""
        if not vulnerabilities:
            return
        
        fieldnames = ['target', 'type', 'severity', 'description', 'scanner', 'timestamp']
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in vulnerabilities:
                row = {
                    'target': vuln.get('target', ''),
                    'type': vuln.get('type', ''),
                    'severity': vuln.get('severity', ''),
                    'description': vuln.get('description', ''),
                    'scanner': vuln.get('scanner', ''),
                    'timestamp': vuln.get('timestamp', '')
                }
                writer.writerow(row)
    
    async def _save_geoip_csv(self, geoip_data, csv_file):
        """Save GeoIP data as CSV"""
        if not geoip_data:
            return
        
        fieldnames = ['ip', 'country', 'city', 'region', 'isp', 'organization', 'threat_level']
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for geo in geoip_data:
                row = {
                    'ip': geo.get('ip', ''),
                    'country': geo.get('country', ''),
                    'city': geo.get('city', ''),
                    'region': geo.get('region', ''),
                    'isp': geo.get('isp', ''),
                    'organization': geo.get('organization', ''),
                    'threat_level': geo.get('threat_level', '')
                }
                writer.writerow(row)
    
    async def _save_packets_csv(self, packets, csv_file):
        """Save packet data as CSV"""
        if not packets:
            return
        
        fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'size']
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for packet in packets:
                row = {
                    'timestamp': packet.get('timestamp', ''),
                    'src_ip': packet.get('src_ip', ''),
                    'dst_ip': packet.get('dst_ip', ''),
                    'src_port': packet.get('src_port', ''),
                    'dst_port': packet.get('dst_port', ''),
                    'protocol': packet.get('protocol', ''),
                    'size': packet.get('size', '')
                }
                writer.writerow(row)
    
    def get_recent_logs(self, count=50):
        """Get recent log entries"""
        return self.session_logs[-count:] if self.session_logs else []
    
    def save_session_report(self):
        """Save session summary report"""
        session_report = {
            'session_id': self.session_id,
            'start_time': self.session_logs[0]['timestamp'] if self.session_logs else None,
            'end_time': datetime.now().isoformat(),
            'total_logs': len(self.session_logs),
            'log_levels': self._count_log_levels(),
            'modules_used': list(set(log['module'] for log in self.session_logs)),
            'logs': self.session_logs
        }
        
        session_file = self.output_dir / "sessions" / f"session_{self.session_id}.json"
        
        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump(session_report, f, indent=2, default=str)
    
    def _count_log_levels(self):
        """Count log entries by level"""
        levels = {}
        for log in self.session_logs:
            level = log['level']
            levels[level] = levels.get(level, 0) + 1
        return levels
    
    def get_log_statistics(self):
        """Get logging statistics"""
        return {
            'session_id': self.session_id,
            'total_logs': len(self.session_logs),
            'log_levels': self._count_log_levels(),
            'output_directory': str(self.output_dir),
            'files_created': len(list(self.output_dir.rglob('*')))
        }