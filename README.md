# 🌐🧿 Mauritania Eye - Hypervision Mode

**Professional Network Intelligence Framework**  
*Advanced Command-Line Network Monitoring and Analysis Tool*

**Author:** Mohamed Lemine Ahmed Jidou 🇲🇷  
**Version:** 3.0.0  
**Target Platform:** debian  Environment

---

## 🎯 Overview

Mauritania Eye Hypervision Mode is a comprehensive cybersecurity intelligence platform designed for network monitoring, vulnerability assessment, and threat analysis. This professional-grade command-line tool integrates multiple security modules into a unified framework for offensive and defensive cybersecurity operations.

## ✨ Key Features

### 🔍 **Real-time Network Monitoring**
- **Packet Sniffing**: Live traffic analysis using Scapy with protocol detection
- **Network Discovery**: Automated host discovery and service enumeration
- **Port Monitoring**: Real-time port and service monitoring with anomaly detection
- **System Monitoring**: Resource usage tracking with performance alerts

### 🛡️ **Security Assessment**
- **Vulnerability Scanning**: Web application security assessment with Nikto integration
- **Network Scanning**: Comprehensive port scanning with service detection
- **Spoofing Detection**: ARP and DNS spoofing detection with real-time alerts
- **Device Fingerprinting**: Advanced device identification and OS detection

### 🌍 **Intelligence Gathering**
- **GeoIP Analysis**: Geographic IP analysis with threat level assessment
- **WHOIS Lookup**: Comprehensive domain and IP intelligence
- **Threat Assessment**: Automated threat scoring based on multiple factors
- **MAC Vendor Lookup**: Device vendor identification and classification

### 📊 **Reporting & Analytics**
- **Multi-format Reports**: JSON and CSV export capabilities
- **Real-time Dashboards**: Live monitoring with Rich terminal interface
- **Session Logging**: Comprehensive activity logging and audit trails
- **Alert Management**: Centralized security alert handling

## 🚀 Quick Start

### Prerequisites
- **Operating System**: Kali Linux (recommended) or Debian-based system
- **Python**: Version 3.7 or higher
- **Privileges**: Root access required for packet capture and some network operations
- **Network Tools**: Nmap, Nikto, Wireshark/Tshark (installed automatically)

### Installation

```bash
# Clone or download the Mauritania Eye framework
git clone <repository-url>
cd mauritania-eye-hypervision

# Run the automated installation script
chmod +x install.sh
./install.sh

# Activate the virtual environment
source activate_mauritania_eye.sh
```

### Manual Installation

```bash
# Install system dependencies
sudo apt update && sudo apt install -y python3 python3-pip nmap nikto wireshark tshark

# Install Python dependencies
pip3 install -r requirements.txt

# Set packet capture permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Make executable
chmod +x mauritania_eye.py
```

## 🔧 Usage

### Command Line Options

```bash
python3 mauritania_eye.py [OPTIONS]

Options:
  --auto                    Run automated comprehensive scan
  --manual                  Run interactive manual mode
  --target TARGET           Target network or IP (e.g., 192.168.1.0/24)
  --interface INTERFACE     Network interface to use (default: eth0)
  --config CONFIG           Configuration file path (default: config.json)
  --output OUTPUT           Output directory for logs and reports (default: logs)
  --verbose, -v             Enable verbose output
  --help                    Show help message and exit
```

### Usage Examples

#### Automated Comprehensive Scan
```bash
# Full network intelligence gathering
sudo python3 mauritania_eye.py --auto

# Scan specific network range
sudo python3 mauritania_eye.py --auto --target 192.168.1.0/24

# Use specific interface
sudo python3 mauritania_eye.py --auto --interface wlan0
```

#### Interactive Manual Mode
```bash
# Start interactive mode
python3 mauritania_eye.py --manual

# Manual mode with custom config
python3 mauritania_eye.py --manual --config custom_config.json
```

#### Module-Specific Operations
```bash
# Network discovery only
python3 mauritania_eye.py --manual
# Then select option 2 (Network Scanner)

# Vulnerability assessment
python3 mauritania_eye.py --manual
# Then select option 3 (Vulnerability Scanner)
```

## 🏗️ Architecture

### Module Structure
```
mauritania_eye.py           # Main controller and CLI interface
├── modules/
│   ├── packet_sniffer.py      # Real-time packet capture and analysis
│   ├── network_scanner.py     # Network discovery and port scanning
│   ├── vulnerability_scanner.py # Security vulnerability assessment
│   ├── port_monitor.py        # Port and service monitoring
│   ├── spoofing_detector.py   # ARP/DNS spoofing detection
│   ├── geoip_analyzer.py      # Geographic IP analysis
│   ├── device_fingerprinter.py # Device identification
│   ├── system_monitor.py      # System resource monitoring
│   ├── logger.py              # Centralized logging system
│   └── config_manager.py      # Configuration management
├── config.json             # Configuration file
├── requirements.txt        # Python dependencies
└── logs/                   # Output directory
    ├── reports/           # Analysis reports (JSON/CSV)
    ├── packets/           # Packet capture logs
    ├── alerts/            # Security alerts
    └── sessions/          # Session logs
```

### Core Modules

#### 1. Packet Sniffer (`packet_sniffer.py`)
- **Real-time packet capture** using Scapy
- **Protocol analysis** (TCP, UDP, ICMP, ARP, DNS)
- **Anomaly detection** for suspicious traffic patterns
- **Live statistics** with Rich terminal interface

#### 2. Network Scanner (`network_scanner.py`)
- **Host discovery** using Nmap integration
- **Port scanning** with service detection
- **OS fingerprinting** and version detection
- **Network topology mapping**

#### 3. Vulnerability Scanner (`vulnerability_scanner.py`)
- **Nikto integration** for web vulnerability assessment
- **Custom security checks** for common vulnerabilities
- **Network-level vulnerability detection**
- **Risk scoring** and prioritization

#### 4. Spoofing Detector (`spoofing_detector.py`)
- **ARP spoofing detection** with MAC address monitoring
- **DNS spoofing detection** with response analysis
- **Real-time alerting** for security incidents
- **Pattern analysis** for advanced attack detection

#### 5. GeoIP Analyzer (`geoip_analyzer.py`)
- **Geographic IP mapping** with threat assessment
- **WHOIS data integration** for comprehensive intelligence
- **Threat scoring** based on geographic and organizational factors
- **ISP and organization analysis**

## ⚙️ Configuration

### Configuration File (`config.json`)

The framework uses a comprehensive JSON configuration file to customize behavior:

```json
{
  "general": {
    "interface": "eth0",
    "output_directory": "logs",
    "verbose": false,
    "auto_save": true
  },
  "packet_sniffer": {
    "enabled": true,
    "capture_duration": 60,
    "filter": "",
    "max_packets": 1000
  },
  "network_scanner": {
    "enabled": true,
    "scan_timeout": 30,
    "port_range": "1-1000",
    "scan_type": "syn"
  },
  "vulnerability_scanner": {
    "enabled": true,
    "nikto_enabled": true,
    "custom_checks": true,
    "scan_timeout": 300
  },
  "alerts": {
    "critical_threshold": 90,
    "warning_threshold": 75,
    "email_notifications": false,
    "log_all_alerts": true
  }
}
```

### Module Configuration

Each module can be individually configured:

- **Enable/disable modules** based on requirements
- **Adjust timeouts** for different network conditions
- **Configure alert thresholds** for security monitoring
- **Customize output formats** and retention policies

## 📊 Output and Reporting

### Report Formats

#### JSON Reports
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "scan_type": "comprehensive",
  "results": {
    "network_discovery": [...],
    "vulnerabilities": [...],
    "geoip_analysis": [...]
  },
  "summary": {
    "total_hosts": 15,
    "vulnerabilities_found": 3,
    "threat_level": "medium"
  }
}
```

#### CSV Reports
- **Network Discovery**: Host information with services
- **Vulnerability Assessment**: Security findings with risk scores
- **GeoIP Analysis**: Geographic and threat intelligence
- **Packet Analysis**: Traffic statistics and anomalies

### Log Files

#### Session Logs
- **Activity tracking** with timestamps
- **Module execution** logs
- **Error handling** and debugging information
- **Performance metrics**

#### Security Alerts
- **Real-time alerts** for security incidents
- **Threat classification** with severity levels
- **Incident correlation** across modules
- **Response recommendations**

## 🔒 Security Considerations

### Ethical Usage
- **Authorization Required**: Only use on networks you own or have explicit permission to monitor
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Report vulnerabilities through proper channels

### Operational Security
- **Privilege Management**: Run with minimal required privileges
- **Data Protection**: Secure storage of captured data and reports
- **Network Impact**: Monitor resource usage to avoid network disruption
- **Audit Trails**: Maintain comprehensive logs for accountability

### Privacy Protection
- **Data Minimization**: Capture only necessary information
- **Retention Policies**: Implement appropriate data retention limits
- **Access Control**: Restrict access to sensitive monitoring data
- **Anonymization**: Consider data anonymization for analysis

## 🛠️ Advanced Features

### Custom Module Development

The framework supports custom module development:

```python
class CustomModule:
    def __init__(self, logger):
        self.logger = logger
    
    async def custom_analysis(self):
        # Implement custom analysis logic
        pass
```

### Integration Capabilities

- **API Integration**: REST API for external tool integration
- **Database Support**: Export to various database formats
- **SIEM Integration**: Compatible with security information systems
- **Automation**: Scriptable for automated security operations

### Performance Optimization

- **Asynchronous Operations**: Non-blocking I/O for better performance
- **Memory Management**: Efficient handling of large datasets
- **Caching**: Intelligent caching for repeated operations
- **Resource Monitoring**: Built-in performance monitoring

## 🔧 Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Fix packet capture permissions
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Or run with sudo
sudo python3 mauritania_eye.py --auto
```

#### Missing Dependencies
```bash
# Install missing tools
sudo apt install nmap nikto wireshark

# Update Python packages
pip3 install --upgrade -r requirements.txt
```

#### Network Interface Issues
```bash
# List available interfaces
ip link show

# Update config.json with correct interface
{
  "general": {
    "interface": "wlan0"  # Use correct interface
  }
}
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
python3 mauritania_eye.py --auto --verbose
```

### Log Analysis

Check logs for detailed error information:

```bash
# View session logs
cat logs/sessions/session_YYYYMMDD_HHMMSS.json

# Check error logs
grep ERROR logs/mauritania_eye_YYYYMMDD.log
```

## 🤝 Contributing

We welcome contributions to improve Mauritania Eye Hypervision Mode:

### Development Guidelines
- **Code Quality**: Follow PEP 8 style guidelines
- **Documentation**: Comprehensive docstrings and comments
- **Testing**: Include unit tests for new functionality
- **Security**: Security-first development approach

### Contribution Process
1. **Fork** the repository
2. **Create** a feature branch
3. **Implement** changes with tests
4. **Document** new features
5. **Submit** a pull request

### Areas for Contribution
- **New Modules**: Additional security analysis capabilities
- **Integration**: Support for new tools and platforms
- **Performance**: Optimization and efficiency improvements
- **Documentation**: User guides and tutorials

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Nmap**: Network discovery and security auditing
- **Nikto**: Web server scanner
- **Rich**: Beautiful terminal formatting
- **Python Community**: Excellent libraries and tools

## 📞 Support

For support and questions:

- **Documentation**: Comprehensive guides in `/docs`
- **Issues**: GitHub issue tracker for bug reports
- **Discussions**: Community discussions for feature requests
- **Security**: Responsible disclosure for security issues

## 🔮 Future Enhancements

### Planned Features
- **Machine Learning**: AI-powered threat detection
- **Cloud Integration**: AWS/Azure security service integration
- **Mobile Support**: Android/iOS companion applications
- **Distributed Scanning**: Multi-node scanning capabilities

### Research Areas
- **Behavioral Analysis**: Advanced anomaly detection
- **Threat Intelligence**: External feed integration
- **Automation**: Intelligent response systems
- **Visualization**: Advanced data visualization

---

## 🌐🧿 **Mauritania Eye - Hypervision Mode**
*Professional Network Intelligence Framework*  
*Made with ❤️ by Mohamed Lemine Ahmed Jidou 🇲🇷*

**Version:** 3.0.0  
**License:** MIT  
**Platform:** Debian Terminal

---

*For professional cybersecurity operations, authorized penetration testing, and network security research.*
