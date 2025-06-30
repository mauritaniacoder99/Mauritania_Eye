#!/usr/bin/env python3
"""
Mauritania Eye - System Monitor Module
Real-time system resource and network monitoring

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import asyncio
import time
import psutil
import subprocess
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn
from collections import deque

class SystemMonitor:
    """
    System resource and network monitoring module
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.console = Console()
        self.running = False
        self.monitoring_data = deque(maxlen=100)  # Store last 100 data points
        
    async def start_monitoring(self, duration=300, interval=2):
        """Start real-time system monitoring"""
        self.console.print(Panel("📊 Starting System Monitoring", style="bold green"))
        
        self.running = True
        start_time = time.time()
        
        def generate_monitoring_display():
            # Get current system stats
            stats = self._get_system_stats()
            network_stats = self._get_network_stats()
            process_stats = self._get_top_processes()
            
            # Create layout
            layout_table = Table.grid()
            layout_table.add_column()
            layout_table.add_column()
            
            # System resources table
            sys_table = Table(title="💻 System Resources")
            sys_table.add_column("Resource", style="cyan")
            sys_table.add_column("Usage", style="yellow")
            sys_table.add_column("Available", style="green")
            
            # CPU
            cpu_percent = stats['cpu_percent']
            cpu_color = self._get_usage_color(cpu_percent)
            sys_table.add_row(
                "CPU",
                f"[{cpu_color}]{cpu_percent:.1f}%[/{cpu_color}]",
                f"{stats['cpu_count']} cores"
            )
            
            # Memory
            mem_percent = stats['memory_percent']
            mem_color = self._get_usage_color(mem_percent)
            sys_table.add_row(
                "Memory",
                f"[{mem_color}]{mem_percent:.1f}%[/{mem_color}]",
                f"{stats['memory_available']:.1f} GB"
            )
            
            # Disk
            disk_percent = stats['disk_percent']
            disk_color = self._get_usage_color(disk_percent)
            sys_table.add_row(
                "Disk",
                f"[{disk_color}]{disk_percent:.1f}%[/{disk_color}]",
                f"{stats['disk_free']:.1f} GB"
            )
            
            # Network table
            net_table = Table(title="🌐 Network Activity")
            net_table.add_column("Interface", style="cyan")
            net_table.add_column("Bytes Sent", style="green")
            net_table.add_column("Bytes Recv", style="yellow")
            net_table.add_column("Packets", style="magenta")
            
            for iface, data in network_stats.items():
                net_table.add_row(
                    iface,
                    self._format_bytes(data['bytes_sent']),
                    self._format_bytes(data['bytes_recv']),
                    f"{data['packets_sent'] + data['packets_recv']}"
                )
            
            # Top processes table
            proc_table = Table(title="🔝 Top Processes")
            proc_table.add_column("PID", style="cyan")
            proc_table.add_column("Name", style="white")
            proc_table.add_column("CPU%", style="red")
            proc_table.add_column("Memory%", style="yellow")
            
            for proc in process_stats[:5]:  # Top 5 processes
                proc_table.add_row(
                    str(proc['pid']),
                    proc['name'][:20],
                    f"{proc['cpu_percent']:.1f}",
                    f"{proc['memory_percent']:.1f}"
                )
            
            # Combine tables
            layout_table.add_row(sys_table, net_table)
            layout_table.add_row(proc_table, "")
            
            return layout_table
        
        # Display real-time monitoring
        with Live(generate_monitoring_display(), refresh_per_second=0.5) as live:
            while self.running and (time.time() - start_time) < duration:
                await asyncio.sleep(interval)
                
                # Collect data point
                data_point = {
                    'timestamp': datetime.now().isoformat(),
                    'system': self._get_system_stats(),
                    'network': self._get_network_stats(),
                    'processes': self._get_top_processes()
                }
                self.monitoring_data.append(data_point)
                
                # Update display
                live.update(generate_monitoring_display())
        
        self.running = False
        await self._generate_monitoring_report()
    
    def _get_system_stats(self):
        """Get current system statistics"""
        try:
            # CPU stats
            cpu_percent = psutil.cpu_percent(interval=None)
            cpu_count = psutil.cpu_count()
            
            # Memory stats
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available / (1024**3)  # GB
            memory_total = memory.total / (1024**3)  # GB
            
            # Disk stats
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_free = disk.free / (1024**3)  # GB
            disk_total = disk.total / (1024**3)  # GB
            
            # Load average (Unix-like systems)
            load_avg = None
            try:
                load_avg = psutil.getloadavg()
            except AttributeError:
                pass  # Windows doesn't have load average
            
            return {
                'cpu_percent': cpu_percent,
                'cpu_count': cpu_count,
                'memory_percent': memory_percent,
                'memory_available': memory_available,
                'memory_total': memory_total,
                'disk_percent': disk_percent,
                'disk_free': disk_free,
                'disk_total': disk_total,
                'load_avg': load_avg
            }
            
        except Exception as e:
            self.logger.log_error("SystemMonitor", f"Error getting system stats: {str(e)}")
            return {}
    
    def _get_network_stats(self):
        """Get network interface statistics"""
        try:
            net_io = psutil.net_io_counters(pernic=True)
            network_stats = {}
            
            for interface, stats in net_io.items():
                # Skip loopback and inactive interfaces
                if interface.startswith('lo') or stats.bytes_sent == 0 and stats.bytes_recv == 0:
                    continue
                
                network_stats[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'errin': stats.errin,
                    'errout': stats.errout,
                    'dropin': stats.dropin,
                    'dropout': stats.dropout
                }
            
            return network_stats
            
        except Exception as e:
            self.logger.log_error("SystemMonitor", f"Error getting network stats: {str(e)}")
            return {}
    
    def _get_top_processes(self):
        """Get top processes by CPU and memory usage"""
        try:
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] is not None:
                        processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
            
            return processes[:10]  # Top 10 processes
            
        except Exception as e:
            self.logger.log_error("SystemMonitor", f"Error getting process stats: {str(e)}")
            return []
    
    def _get_usage_color(self, percentage):
        """Get color based on usage percentage"""
        if percentage >= 90:
            return 'bright_red'
        elif percentage >= 75:
            return 'red'
        elif percentage >= 50:
            return 'yellow'
        else:
            return 'green'
    
    def _format_bytes(self, bytes_value):
        """Format bytes into human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    async def get_network_bandwidth(self, interface="eth0", duration=10):
        """Measure network bandwidth for specific interface"""
        self.console.print(Panel(f"📈 Measuring Bandwidth on {interface}", style="bold blue"))
        
        try:
            # Get initial stats
            initial_stats = psutil.net_io_counters(pernic=True).get(interface)
            if not initial_stats:
                self.console.print(f"[red]Interface {interface} not found[/red]")
                return None
            
            initial_time = time.time()
            initial_bytes_sent = initial_stats.bytes_sent
            initial_bytes_recv = initial_stats.bytes_recv
            
            # Wait for measurement period
            await asyncio.sleep(duration)
            
            # Get final stats
            final_stats = psutil.net_io_counters(pernic=True).get(interface)
            final_time = time.time()
            final_bytes_sent = final_stats.bytes_sent
            final_bytes_recv = final_stats.bytes_recv
            
            # Calculate bandwidth
            time_diff = final_time - initial_time
            bytes_sent_diff = final_bytes_sent - initial_bytes_sent
            bytes_recv_diff = final_bytes_recv - initial_bytes_recv
            
            upload_speed = bytes_sent_diff / time_diff  # bytes per second
            download_speed = bytes_recv_diff / time_diff  # bytes per second
            
            # Display results
            bandwidth_table = Table(title=f"Bandwidth Measurement - {interface}")
            bandwidth_table.add_column("Direction", style="cyan")
            bandwidth_table.add_column("Speed", style="yellow")
            bandwidth_table.add_column("Total Bytes", style="green")
            
            bandwidth_table.add_row(
                "Upload",
                f"{self._format_bytes(upload_speed)}/s",
                self._format_bytes(bytes_sent_diff)
            )
            
            bandwidth_table.add_row(
                "Download",
                f"{self._format_bytes(download_speed)}/s",
                self._format_bytes(bytes_recv_diff)
            )
            
            self.console.print(bandwidth_table)
            
            return {
                'interface': interface,
                'duration': duration,
                'upload_speed': upload_speed,
                'download_speed': download_speed,
                'total_sent': bytes_sent_diff,
                'total_recv': bytes_recv_diff
            }
            
        except Exception as e:
            self.logger.log_error("SystemMonitor", f"Bandwidth measurement error: {str(e)}")
            return None
    
    async def monitor_interface_traffic(self, interface="eth0", duration=60):
        """Monitor traffic on specific interface with real-time graph"""
        self.console.print(Panel(f"📊 Monitoring Traffic on {interface}", style="bold green"))
        
        traffic_history = deque(maxlen=50)  # Keep last 50 data points
        
        def generate_traffic_display():
            if not traffic_history:
                return "Collecting data..."
            
            # Create traffic table
            traffic_table = Table(title=f"Interface {interface} Traffic")
            traffic_table.add_column("Metric", style="cyan")
            traffic_table.add_column("Current", style="yellow")
            traffic_table.add_column("Average", style="green")
            traffic_table.add_column("Peak", style="red")
            
            # Calculate statistics
            current = traffic_history[-1]
            upload_speeds = [d['upload_speed'] for d in traffic_history]
            download_speeds = [d['download_speed'] for d in traffic_history]
            
            avg_upload = sum(upload_speeds) / len(upload_speeds)
            avg_download = sum(download_speeds) / len(download_speeds)
            peak_upload = max(upload_speeds)
            peak_download = max(download_speeds)
            
            traffic_table.add_row(
                "Upload",
                f"{self._format_bytes(current['upload_speed'])}/s",
                f"{self._format_bytes(avg_upload)}/s",
                f"{self._format_bytes(peak_upload)}/s"
            )
            
            traffic_table.add_row(
                "Download",
                f"{self._format_bytes(current['download_speed'])}/s",
                f"{self._format_bytes(avg_download)}/s",
                f"{self._format_bytes(peak_download)}/s"
            )
            
            return traffic_table
        
        # Monitor traffic
        start_time = time.time()
        prev_stats = psutil.net_io_counters(pernic=True).get(interface)
        
        if not prev_stats:
            self.console.print(f"[red]Interface {interface} not found[/red]")
            return
        
        with Live(generate_traffic_display(), refresh_per_second=1) as live:
            while time.time() - start_time < duration:
                await asyncio.sleep(1)
                
                # Get current stats
                current_stats = psutil.net_io_counters(pernic=True).get(interface)
                current_time = time.time()
                
                if current_stats and prev_stats:
                    # Calculate speeds
                    time_diff = 1.0  # 1 second interval
                    upload_speed = (current_stats.bytes_sent - prev_stats.bytes_sent) / time_diff
                    download_speed = (current_stats.bytes_recv - prev_stats.bytes_recv) / time_diff
                    
                    # Store data point
                    traffic_history.append({
                        'timestamp': current_time,
                        'upload_speed': upload_speed,
                        'download_speed': download_speed
                    })
                    
                    # Update display
                    live.update(generate_traffic_display())
                
                prev_stats = current_stats
        
        # Generate traffic report
        if traffic_history:
            await self._generate_traffic_report(interface, list(traffic_history))
    
    async def _generate_monitoring_report(self):
        """Generate comprehensive monitoring report"""
        if not self.monitoring_data:
            return
        
        # Analyze monitoring data
        report = {
            'timestamp': datetime.now().isoformat(),
            'monitoring_duration': len(self.monitoring_data),
            'system_analysis': self._analyze_system_performance(),
            'network_analysis': self._analyze_network_performance(),
            'process_analysis': self._analyze_process_activity(),
            'alerts': self._generate_performance_alerts()
        }
        
        await self.logger.save_report(report, "system_monitoring")
        self._display_monitoring_summary(report)
    
    def _analyze_system_performance(self):
        """Analyze system performance over monitoring period"""
        if not self.monitoring_data:
            return {}
        
        cpu_values = [d['system']['cpu_percent'] for d in self.monitoring_data if 'system' in d]
        memory_values = [d['system']['memory_percent'] for d in self.monitoring_data if 'system' in d]
        disk_values = [d['system']['disk_percent'] for d in self.monitoring_data if 'system' in d]
        
        return {
            'cpu': {
                'average': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                'peak': max(cpu_values) if cpu_values else 0,
                'minimum': min(cpu_values) if cpu_values else 0
            },
            'memory': {
                'average': sum(memory_values) / len(memory_values) if memory_values else 0,
                'peak': max(memory_values) if memory_values else 0,
                'minimum': min(memory_values) if memory_values else 0
            },
            'disk': {
                'average': sum(disk_values) / len(disk_values) if disk_values else 0,
                'peak': max(disk_values) if disk_values else 0,
                'minimum': min(disk_values) if disk_values else 0
            }
        }
    
    def _analyze_network_performance(self):
        """Analyze network performance over monitoring period"""
        if not self.monitoring_data:
            return {}
        
        # Aggregate network data
        total_bytes_sent = 0
        total_bytes_recv = 0
        
        for data_point in self.monitoring_data:
            if 'network' in data_point:
                for interface, stats in data_point['network'].items():
                    total_bytes_sent += stats.get('bytes_sent', 0)
                    total_bytes_recv += stats.get('bytes_recv', 0)
        
        return {
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_recv': total_bytes_recv,
            'total_traffic': total_bytes_sent + total_bytes_recv
        }
    
    def _analyze_process_activity(self):
        """Analyze process activity patterns"""
        if not self.monitoring_data:
            return {}
        
        process_cpu_usage = {}
        
        for data_point in self.monitoring_data:
            if 'processes' in data_point:
                for proc in data_point['processes']:
                    name = proc.get('name', 'unknown')
                    cpu = proc.get('cpu_percent', 0)
                    
                    if name not in process_cpu_usage:
                        process_cpu_usage[name] = []
                    process_cpu_usage[name].append(cpu)
        
        # Calculate average CPU usage per process
        avg_cpu_usage = {}
        for name, cpu_values in process_cpu_usage.items():
            avg_cpu_usage[name] = sum(cpu_values) / len(cpu_values)
        
        # Get top CPU consumers
        top_processes = sorted(avg_cpu_usage.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'top_cpu_processes': top_processes,
            'unique_processes': len(process_cpu_usage)
        }
    
    def _generate_performance_alerts(self):
        """Generate performance alerts based on thresholds"""
        alerts = []
        
        if not self.monitoring_data:
            return alerts
        
        # Check for high resource usage
        latest_data = self.monitoring_data[-1]
        
        if 'system' in latest_data:
            system = latest_data['system']
            
            if system.get('cpu_percent', 0) > 90:
                alerts.append({
                    'type': 'high_cpu_usage',
                    'severity': 'critical',
                    'message': f"CPU usage at {system['cpu_percent']:.1f}%"
                })
            
            if system.get('memory_percent', 0) > 90:
                alerts.append({
                    'type': 'high_memory_usage',
                    'severity': 'critical',
                    'message': f"Memory usage at {system['memory_percent']:.1f}%"
                })
            
            if system.get('disk_percent', 0) > 90:
                alerts.append({
                    'type': 'high_disk_usage',
                    'severity': 'warning',
                    'message': f"Disk usage at {system['disk_percent']:.1f}%"
                })
        
        return alerts
    
    async def _generate_traffic_report(self, interface, traffic_data):
        """Generate traffic monitoring report"""
        if not traffic_data:
            return
        
        upload_speeds = [d['upload_speed'] for d in traffic_data]
        download_speeds = [d['download_speed'] for d in traffic_data]
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'interface': interface,
            'monitoring_duration': len(traffic_data),
            'upload_stats': {
                'average': sum(upload_speeds) / len(upload_speeds),
                'peak': max(upload_speeds),
                'minimum': min(upload_speeds),
                'total': sum(upload_speeds)
            },
            'download_stats': {
                'average': sum(download_speeds) / len(download_speeds),
                'peak': max(download_speeds),
                'minimum': min(download_speeds),
                'total': sum(download_speeds)
            }
        }
        
        await self.logger.save_report(report, f"traffic_monitoring_{interface}")
    
    def _display_monitoring_summary(self, report):
        """Display monitoring summary"""
        self.console.print(Panel("📊 System Monitoring Summary", style="bold blue"))
        
        # System performance summary
        sys_analysis = report.get('system_analysis', {})
        if sys_analysis:
            perf_table = Table(title="System Performance Summary")
            perf_table.add_column("Resource", style="cyan")
            perf_table.add_column("Average", style="yellow")
            perf_table.add_column("Peak", style="red")
            perf_table.add_column("Minimum", style="green")
            
            for resource, stats in sys_analysis.items():
                if isinstance(stats, dict):
                    perf_table.add_row(
                        resource.upper(),
                        f"{stats.get('average', 0):.1f}%",
                        f"{stats.get('peak', 0):.1f}%",
                        f"{stats.get('minimum', 0):.1f}%"
                    )
            
            self.console.print(perf_table)
        
        # Network summary
        net_analysis = report.get('network_analysis', {})
        if net_analysis:
            net_table = Table(title="Network Activity Summary")
            net_table.add_column("Metric", style="cyan")
            net_table.add_column("Value", style="yellow")
            
            net_table.add_row("Total Bytes Sent", self._format_bytes(net_analysis.get('total_bytes_sent', 0)))
            net_table.add_row("Total Bytes Received", self._format_bytes(net_analysis.get('total_bytes_recv', 0)))
            net_table.add_row("Total Traffic", self._format_bytes(net_analysis.get('total_traffic', 0)))
            
            self.console.print(net_table)
        
        # Process summary
        proc_analysis = report.get('process_analysis', {})
        if proc_analysis and proc_analysis.get('top_cpu_processes'):
            proc_table = Table(title="Top CPU Consuming Processes")
            proc_table.add_column("Process", style="cyan")
            proc_table.add_column("Average CPU%", style="red")
            
            for proc_name, avg_cpu in proc_analysis['top_cpu_processes']:
                proc_table.add_row(proc_name, f"{avg_cpu:.1f}%")
            
            self.console.print(proc_table)
        
        # Alerts
        alerts = report.get('alerts', [])
        if alerts:
            self.console.print(f"\n[red]⚠️ {len(alerts)} performance alerts detected![/red]")
            for alert in alerts:
                severity_color = 'bright_red' if alert['severity'] == 'critical' else 'yellow'
                self.console.print(f"  • [{severity_color}]{alert['message']}[/{severity_color}]")
        else:
            self.console.print("\n[green]✅ No performance issues detected[/green]")