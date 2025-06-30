#!/usr/bin/env python3
"""
Mauritania Eye - Hypervision Mode Installation Script
Professional Network Security Tools Automation

Author: Mohamed Lemine Ahmed Jidou 🇲🇷
Version: 2.0.0

This script automates the installation and configuration of network security tools
for the Mauritania Eye Hypervision Mode platform on Kali Linux systems.

IMPORTANT: This script is designed for educational and authorized testing purposes only.
Ensure you have proper authorization before running network security tools.
"""

import os
import sys
import subprocess
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/mauritania-eye-install.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class SecurityToolsInstaller:
    """
    Automated installer for network security monitoring tools
    """
    
    def __init__(self):
        self.tools_config = {
            'zeek': {
                'package': 'zeek',
                'service': 'zeek',
                'config_path': '/opt/zeek/etc',
                'log_path': '/opt/zeek/logs',
                'interface': 'eth0'
            },
            'suricata': {
                'package': 'suricata',
                'service': 'suricata',
                'config_path': '/etc/suricata',
                'log_path': '/var/log/suricata',
                'interface': 'eth0'
            },
            'wireshark': {
                'package': 'wireshark',
                'tshark': 'tshark',
                'capture_path': '/var/captures'
            },
            'netdata': {
                'package': 'netdata',
                'service': 'netdata',
                'config_path': '/etc/netdata',
                'web_port': 19999
            },
            'ntopng': {
                'package': 'ntopng',
                'service': 'ntopng',
                'config_path': '/etc/ntopng',
                'web_port': 3000
            },
            'kismet': {
                'package': 'kismet',
                'service': 'kismet',
                'config_path': '/etc/kismet',
                'log_path': '/var/log/kismet'
            },
            'nmap': {
                'package': 'nmap',
                'scripts_path': '/usr/share/nmap/scripts'
            }
        }
        
        self.mauritania_eye_path = '/opt/mauritania-eye'
        self.config_path = f'{self.mauritania_eye_path}/config'
        self.logs_path = f'{self.mauritania_eye_path}/logs'
        
    def check_root_privileges(self) -> bool:
        """Check if script is running with root privileges"""
        if os.geteuid() != 0:
            logger.error("This script must be run as root (sudo)")
            return False
        return True
    
    def check_kali_linux(self) -> bool:
        """Check if running on Kali Linux"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'kali' in content.lower():
                    logger.info("Kali Linux detected")
                    return True
        except FileNotFoundError:
            pass
        
        logger.warning("Not running on Kali Linux - some tools may not be available")
        return True  # Continue anyway
    
    def update_system(self) -> bool:
        """Update system packages"""
        logger.info("Updating system packages...")
        try:
            subprocess.run(['apt', 'update'], check=True, capture_output=True)
            subprocess.run(['apt', 'upgrade', '-y'], check=True, capture_output=True)
            logger.info("System updated successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update system: {e}")
            return False
    
    def install_package(self, package_name: str) -> bool:
        """Install a package using apt"""
        logger.info(f"Installing {package_name}...")
        try:
            subprocess.run(['apt', 'install', '-y', package_name], 
                         check=True, capture_output=True)
            logger.info(f"{package_name} installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install {package_name}: {e}")
            return False
    
    def create_directories(self) -> bool:
        """Create necessary directories"""
        directories = [
            self.mauritania_eye_path,
            self.config_path,
            self.logs_path,
            '/var/captures',
            '/var/log/mauritania-eye'
        ]
        
        for directory in directories:
            try:
                Path(directory).mkdir(parents=True, exist_ok=True)
                logger.info(f"Created directory: {directory}")
            except Exception as e:
                logger.error(f"Failed to create directory {directory}: {e}")
                return False
        
        return True
    
    def configure_zeek(self) -> bool:
        """Configure Zeek network security monitor"""
        logger.info("Configuring Zeek...")
        
        zeek_config = f"""
# Mauritania Eye - Zeek Configuration
# Network interface to monitor
interface={self.tools_config['zeek']['interface']}

# Log formats
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp

# JSON logging
@load policy/tuning/json-logs.zeek

# Custom logging for Mauritania Eye
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
"""
        
        try:
            config_file = f"{self.config_path}/zeek-mauritania.zeek"
            with open(config_file, 'w') as f:
                f.write(zeek_config)
            
            # Create systemd service
            service_config = f"""[Unit]
Description=Zeek Network Security Monitor for Mauritania Eye
After=network.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeek -i {self.tools_config['zeek']['interface']} {config_file}
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
User=root

[Install]
WantedBy=multi-user.target
"""
            
            with open('/etc/systemd/system/zeek-mauritania.service', 'w') as f:
                f.write(service_config)
            
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            logger.info("Zeek configured successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure Zeek: {e}")
            return False
    
    def configure_suricata(self) -> bool:
        """Configure Suricata IDS/IPS"""
        logger.info("Configuring Suricata...")
        
        suricata_config = f"""
# Mauritania Eye - Suricata Configuration
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: {self.tools_config['suricata']['interface']}
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - smtp
        - ssh
        - flow

logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: /var/log/suricata/suricata.log

rule-files:
  - suricata.rules
  - /var/lib/suricata/rules/emerging-threats.rules
"""
        
        try:
            config_file = f"{self.tools_config['suricata']['config_path']}/suricata-mauritania.yaml"
            with open(config_file, 'w') as f:
                f.write(suricata_config)
            
            # Update Suricata rules
            subprocess.run(['suricata-update'], check=True, capture_output=True)
            
            logger.info("Suricata configured successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure Suricata: {e}")
            return False
    
    def configure_netdata(self) -> bool:
        """Configure Netdata monitoring"""
        logger.info("Configuring Netdata...")
        
        netdata_config = """
[global]
    hostname = mauritania-eye-hypervision
    history = 3600
    update every = 1
    
[web]
    web files owner = netdata
    web files group = netdata
    bind to = *:19999
    allow connections from = localhost 127.0.0.1 192.168.*.*
    
[plugins]
    apps = yes
    proc = yes
    diskspace = yes
    tc = yes
    cgroups = yes
    idlejitter = yes
    checks = yes
"""
        
        try:
            config_file = f"{self.tools_config['netdata']['config_path']}/netdata.conf"
            with open(config_file, 'w') as f:
                f.write(netdata_config)
            
            logger.info("Netdata configured successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure Netdata: {e}")
            return False
    
    def configure_kismet(self) -> bool:
        """Configure Kismet wireless monitoring"""
        logger.info("Configuring Kismet...")
        
        kismet_config = """
# Mauritania Eye - Kismet Configuration
server_name=Mauritania Eye Hypervision
server_description=Wireless Security Monitoring

# Data sources (configure based on available wireless interfaces)
source=wlan0:name=wireless0
source=wlan1:name=wireless1

# Logging
log_types=kismet,pcapng,alert
log_title=Mauritania Eye Wireless Monitoring

# Web interface
httpd_port=2501
httpd_bind_address=127.0.0.1
httpd_home=/usr/share/kismet/httpd/

# GPS (if available)
gps=false

# Alerts
alert=AIRJACKSSID,5/min,1/sec
alert=DHCPNAMECHANGE,5/min,1/sec
alert=DHCPOSCHANGE,5/min,1/sec
alert=BCASTDISCON,5/min,1/sec
alert=CHANCHANGE,5/min,1/sec
alert=DHCPCONFLICT,10/min,1/sec
alert=NETSTUMBLER,1/min,1/sec
alert=LUCENTTEST,5/min,1/sec
alert=DEAUTHFLOOD,5/min,2/sec
alert=DISCONCODEINVALID,5/min,1/sec
alert=DHCPCLIENTID,5/min,1/sec
"""
        
        try:
            config_file = f"{self.tools_config['kismet']['config_path']}/kismet_mauritania.conf"
            with open(config_file, 'w') as f:
                f.write(kismet_config)
            
            logger.info("Kismet configured successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure Kismet: {e}")
            return False
    
    def create_mauritania_eye_service(self) -> bool:
        """Create main Mauritania Eye service"""
        logger.info("Creating Mauritania Eye service...")
        
        service_script = f"""#!/usr/bin/env python3
import json
import time
import subprocess
from pathlib import Path

class MauritaniaEyeService:
    def __init__(self):
        self.log_parsers = {{
            'zeek': self.parse_zeek_logs,
            'suricata': self.parse_suricata_logs,
            'kismet': self.parse_kismet_logs
        }}
        
    def parse_zeek_logs(self):
        # Parse Zeek JSON logs
        zeek_log_path = "/opt/zeek/logs/current"
        if Path(zeek_log_path).exists():
            # Process conn.log, dns.log, http.log, etc.
            pass
    
    def parse_suricata_logs(self):
        # Parse Suricata EVE JSON logs
        suricata_log = "/var/log/suricata/eve.json"
        if Path(suricata_log).exists():
            # Process alerts, flows, DNS, HTTP, etc.
            pass
    
    def parse_kismet_logs(self):
        # Parse Kismet logs
        kismet_log_path = "/var/log/kismet"
        if Path(kismet_log_path).exists():
            # Process wireless network data
            pass
    
    def aggregate_data(self):
        # Aggregate data from all sources
        aggregated_data = {{
            'timestamp': time.time(),
            'alerts': [],
            'flows': [],
            'vulnerabilities': [],
            'wireless_networks': []
        }}
        
        # Save to Mauritania Eye data directory
        output_file = "/opt/mauritania-eye/data/current.json"
        with open(output_file, 'w') as f:
            json.dump(aggregated_data, f, indent=2)
    
    def run(self):
        while True:
            try:
                for tool, parser in self.log_parsers.items():
                    parser()
                
                self.aggregate_data()
                time.sleep(5)  # Update every 5 seconds
                
            except Exception as e:
                print(f"Error in Mauritania Eye service: {{e}}")
                time.sleep(10)

if __name__ == "__main__":
    service = MauritaniaEyeService()
    service.run()
"""
        
        try:
            service_file = f"{self.mauritania_eye_path}/mauritania_eye_service.py"
            with open(service_file, 'w') as f:
                f.write(service_script)
            
            os.chmod(service_file, 0o755)
            
            # Create systemd service
            systemd_service = f"""[Unit]
Description=Mauritania Eye Hypervision Mode Service
After=network.target zeek-mauritania.service suricata.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {service_file}
Restart=always
User=root
WorkingDirectory={self.mauritania_eye_path}

[Install]
WantedBy=multi-user.target
"""
            
            with open('/etc/systemd/system/mauritania-eye.service', 'w') as f:
                f.write(systemd_service)
            
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            logger.info("Mauritania Eye service created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create Mauritania Eye service: {e}")
            return False
    
    def create_api_server(self) -> bool:
        """Create API server for data access"""
        logger.info("Creating API server...")
        
        api_server = f"""#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
from pathlib import Path

class MauritaniaEyeAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/status':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            status = {{
                'status': 'active',
                'services': {{
                    'zeek': self.check_service('zeek-mauritania'),
                    'suricata': self.check_service('suricata'),
                    'netdata': self.check_service('netdata'),
                    'kismet': self.check_service('kismet')
                }}
            }}
            
            self.wfile.write(json.dumps(status).encode())
            
        elif self.path == '/api/data':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            data_file = "/opt/mauritania-eye/data/current.json"
            if Path(data_file).exists():
                with open(data_file, 'r') as f:
                    data = f.read()
                self.wfile.write(data.encode())
            else:
                self.wfile.write(json.dumps({{'error': 'No data available'}}).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def check_service(self, service_name):
        try:
            result = os.system(f'systemctl is-active --quiet {{service_name}}')
            return 'active' if result == 0 else 'inactive'
        except:
            return 'unknown'

def run_server():
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, MauritaniaEyeAPIHandler)
    print("Mauritania Eye API Server running on port 8080")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
"""
        
        try:
            api_file = f"{self.mauritania_eye_path}/api_server.py"
            with open(api_file, 'w') as f:
                f.write(api_server)
            
            os.chmod(api_file, 0o755)
            
            # Create systemd service for API
            api_service = f"""[Unit]
Description=Mauritania Eye API Server
After=network.target mauritania-eye.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {api_file}
Restart=always
User=root
WorkingDirectory={self.mauritania_eye_path}

[Install]
WantedBy=multi-user.target
"""
            
            with open('/etc/systemd/system/mauritania-eye-api.service', 'w') as f:
                f.write(api_service)
            
            subprocess.run(['systemctl', 'daemon-reload'], check=True)
            logger.info("API server created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create API server: {e}")
            return False
    
    def start_services(self) -> bool:
        """Start all services"""
        services = [
            'zeek-mauritania',
            'suricata',
            'netdata',
            'kismet',
            'mauritania-eye',
            'mauritania-eye-api'
        ]
        
        for service in services:
            try:
                subprocess.run(['systemctl', 'enable', service], check=True)
                subprocess.run(['systemctl', 'start', service], check=True)
                logger.info(f"Started service: {service}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to start service {service}: {e}")
                return False
        
        return True
    
    def install_all_tools(self) -> bool:
        """Install all security tools"""
        logger.info("Starting Mauritania Eye Hypervision Mode installation...")
        
        # Check prerequisites
        if not self.check_root_privileges():
            return False
        
        self.check_kali_linux()
        
        # Update system
        if not self.update_system():
            return False
        
        # Create directories
        if not self.create_directories():
            return False
        
        # Install packages
        packages = ['zeek', 'suricata', 'wireshark', 'tshark', 'netdata', 'ntopng', 'kismet', 'nmap']
        for package in packages:
            if not self.install_package(package):
                logger.warning(f"Failed to install {package}, continuing...")
        
        # Configure tools
        self.configure_zeek()
        self.configure_suricata()
        self.configure_netdata()
        self.configure_kismet()
        
        # Create Mauritania Eye services
        self.create_mauritania_eye_service()
        self.create_api_server()
        
        # Start services
        self.start_services()
        
        logger.info("Mauritania Eye Hypervision Mode installation completed!")
        logger.info("Access the dashboard at: http://localhost:5173")
        logger.info("API endpoint: http://localhost:8080/api/status")
        logger.info("Netdata monitoring: http://localhost:19999")
        
        return True

def main():
    print("🌐🧿 Mauritania Eye - Hypervision Mode Installation")
    print("Professional Network Security Monitoring Platform")
    print("Author: Mohamed Lemine Ahmed Jidou 🇲🇷")
    print("=" * 60)
    
    installer = SecurityToolsInstaller()
    
    try:
        success = installer.install_all_tools()
        if success:
            print("\\n✅ Installation completed successfully!")
            print("\\n🚀 Next steps:")
            print("1. Configure network interfaces in tool configs")
            print("2. Update firewall rules if necessary")
            print("3. Access the web dashboard")
            print("4. Review logs in /var/log/mauritania-eye/")
        else:
            print("\\n❌ Installation failed. Check logs for details.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\\n⚠️  Installation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()