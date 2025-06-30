"""
Mauritania Eye - Network Intelligence Framework Modules
Author: Mohamed Lemine Ahmed Jidou 🇲🇷
"""

__version__ = "3.0.0"
__author__ = "Mohamed Lemine Ahmed Jidou"
__email__ = "mauritania.eye@cybersec.mr"

# Module imports
from .packet_sniffer import PacketSniffer
from .network_scanner import NetworkScanner
from .vulnerability_scanner import VulnerabilityScanner
from .port_monitor import PortMonitor
from .spoofing_detector import SpoofingDetector
from .geoip_analyzer import GeoIPAnalyzer
from .device_fingerprinter import DeviceFingerprinter
from .system_monitor import SystemMonitor
from .logger import MauritaniaLogger
from .config_manager import ConfigManager

__all__ = [
    'PacketSniffer',
    'NetworkScanner', 
    'VulnerabilityScanner',
    'PortMonitor',
    'SpoofingDetector',
    'GeoIPAnalyzer',
    'DeviceFingerprinter',
    'SystemMonitor',
    'MauritaniaLogger',
    'ConfigManager'
]