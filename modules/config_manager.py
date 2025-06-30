#!/usr/bin/env python3
"""
Mauritania Eye - Configuration Manager Module
Configuration management and settings

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

import json
import os
from pathlib import Path

class ConfigManager:
    """
    Configuration management for Mauritania Eye
    """
    
    def __init__(self):
        self.config = self._get_default_config()
        self.config_file = None
    
    def _get_default_config(self):
        """Get default configuration"""
        return {
            "general": {
                "interface": "eth0",
                "output_directory": "logs",
                "verbose": False,
                "auto_save": True
            },
            "packet_sniffer": {
                "enabled": True,
                "capture_duration": 60,
                "filter": "",
                "max_packets": 1000
            },
            "network_scanner": {
                "enabled": True,
                "scan_timeout": 30,
                "port_range": "1-1000",
                "scan_type": "syn"
            },
            "vulnerability_scanner": {
                "enabled": True,
                "nikto_enabled": True,
                "custom_checks": True,
                "scan_timeout": 300
            },
            "port_monitor": {
                "enabled": True,
                "monitoring_interval": 5,
                "alert_threshold": 50
            },
            "spoofing_detector": {
                "enabled": True,
                "arp_monitoring": True,
                "dns_monitoring": True,
                "alert_sensitivity": "medium"
            },
            "geoip_analyzer": {
                "enabled": True,
                "use_online_api": True,
                "cache_results": True
            },
            "device_fingerprinter": {
                "enabled": True,
                "os_detection": True,
                "service_analysis": True
            },
            "system_monitor": {
                "enabled": True,
                "monitoring_interval": 2,
                "resource_alerts": True
            },
            "alerts": {
                "critical_threshold": 90,
                "warning_threshold": 75,
                "email_notifications": False,
                "log_all_alerts": True
            },
            "reporting": {
                "auto_generate": True,
                "formats": ["json", "csv"],
                "retention_days": 30
            }
        }
    
    def load_config(self, config_file):
        """Load configuration from file"""
        self.config_file = Path(config_file)
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                
                # Merge with default config
                self._merge_config(self.config, loaded_config)
                
                return True
                
            except Exception as e:
                print(f"Error loading config file: {e}")
                return False
        else:
            # Create default config file
            self.save_config()
            return True
    
    def save_config(self, config_file=None):
        """Save current configuration to file"""
        if config_file:
            self.config_file = Path(config_file)
        
        if not self.config_file:
            self.config_file = Path("config.json")
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            
            return True
            
        except Exception as e:
            print(f"Error saving config file: {e}")
            return False
    
    def _merge_config(self, default, loaded):
        """Recursively merge loaded config with default"""
        for key, value in loaded.items():
            if key in default:
                if isinstance(value, dict) and isinstance(default[key], dict):
                    self._merge_config(default[key], value)
                else:
                    default[key] = value
            else:
                default[key] = value
    
    def get(self, section, key=None, default=None):
        """Get configuration value"""
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def set(self, section, key, value):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
    
    def is_module_enabled(self, module_name):
        """Check if a module is enabled"""
        return self.get(module_name, "enabled", True)
    
    def get_interface(self):
        """Get network interface"""
        return self.get("general", "interface", "eth0")
    
    def get_output_directory(self):
        """Get output directory"""
        return self.get("general", "output_directory", "logs")
    
    def is_verbose(self):
        """Check if verbose mode is enabled"""
        return self.get("general", "verbose", False)
    
    def get_scan_timeout(self):
        """Get scan timeout"""
        return self.get("network_scanner", "scan_timeout", 30)
    
    def get_monitoring_interval(self):
        """Get monitoring interval"""
        return self.get("system_monitor", "monitoring_interval", 2)
    
    def get_alert_thresholds(self):
        """Get alert thresholds"""
        return {
            'critical': self.get("alerts", "critical_threshold", 90),
            'warning': self.get("alerts", "warning_threshold", 75)
        }
    
    def create_sample_config(self, filename="config.json"):
        """Create a sample configuration file"""
        sample_config = self._get_default_config()
        
        # Add comments as special keys (will be ignored by JSON parser)
        sample_config["_comments"] = {
            "general": "General application settings",
            "packet_sniffer": "Packet capture and analysis settings",
            "network_scanner": "Network discovery and port scanning",
            "vulnerability_scanner": "Security vulnerability assessment",
            "alerts": "Alert and notification settings"
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(sample_config, f, indent=2)
            
            print(f"Sample configuration created: {filename}")
            return True
            
        except Exception as e:
            print(f"Error creating sample config: {e}")
            return False
    
    def validate_config(self):
        """Validate current configuration"""
        errors = []
        
        # Validate interface
        interface = self.get_interface()
        if not self._is_valid_interface(interface):
            errors.append(f"Invalid network interface: {interface}")
        
        # Validate output directory
        output_dir = self.get_output_directory()
        try:
            Path(output_dir).mkdir(exist_ok=True)
        except Exception:
            errors.append(f"Cannot create output directory: {output_dir}")
        
        # Validate timeouts
        scan_timeout = self.get_scan_timeout()
        if not isinstance(scan_timeout, int) or scan_timeout <= 0:
            errors.append("Scan timeout must be a positive integer")
        
        # Validate thresholds
        thresholds = self.get_alert_thresholds()
        if thresholds['critical'] <= thresholds['warning']:
            errors.append("Critical threshold must be higher than warning threshold")
        
        return errors
    
    def _is_valid_interface(self, interface):
        """Check if network interface exists"""
        try:
            import psutil
            interfaces = psutil.net_if_addrs().keys()
            return interface in interfaces
        except ImportError:
            # If psutil not available, assume interface is valid
            return True
    
    def get_module_config(self, module_name):
        """Get configuration for specific module"""
        return self.config.get(module_name, {})
    
    def update_module_config(self, module_name, config_updates):
        """Update configuration for specific module"""
        if module_name not in self.config:
            self.config[module_name] = {}
        
        self.config[module_name].update(config_updates)
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self._get_default_config()
    
    def export_config(self, filename):
        """Export current configuration to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception:
            return False
    
    def import_config(self, filename):
        """Import configuration from file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
            
            # Validate imported config
            if isinstance(imported_config, dict):
                self.config = imported_config
                return True
            else:
                return False
                
        except Exception:
            return False