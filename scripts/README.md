# Mauritania Eye - Hypervision Mode Scripts

This directory contains automation scripts for deploying and managing the Mauritania Eye Hypervision Mode network security platform.

## 🔧 Installation Script

### `install_security_tools.py`

Professional-grade automation script for installing and configuring network security tools on Kali Linux systems.

#### Features:
- **Automated Installation**: Installs Zeek, Suricata, Wireshark, Netdata, Ntopng, Kismet, and Nmap
- **Service Configuration**: Configures all tools with optimized settings
- **Systemd Integration**: Creates systemd services for automatic startup
- **API Server**: Provides REST API for data access
- **Log Aggregation**: Centralizes logs from all security tools

#### Usage:

```bash
# Make script executable
chmod +x install_security_tools.py

# Run installation (requires root privileges)
sudo python3 install_security_tools.py
```

#### Prerequisites:
- Kali Linux (recommended) or Debian-based system
- Root privileges (sudo access)
- Python 3.6+
- Internet connection for package downloads

#### What it installs:

1. **Zeek (Bro)** - Network security monitor
   - Behavioral traffic analysis
   - JSON log export
   - Custom configuration for Mauritania Eye

2. **Suricata** - IDS/IPS system
   - Multi-threaded packet inspection
   - Rule-based threat detection
   - EVE JSON logging

3. **Wireshark/Tshark** - Packet analysis
   - Deep packet inspection
   - Protocol analysis
   - Capture file management

4. **Netdata** - Real-time monitoring
   - System performance metrics
   - Network bandwidth monitoring
   - Web-based dashboard

5. **Ntopng** - Network traffic analysis
   - Flow-based monitoring
   - GeoIP integration
   - Historical data analysis

6. **Kismet** - Wireless network monitoring
   - WiFi network discovery
   - Rogue AP detection
   - Wireless security assessment

7. **Nmap** - Network scanner
   - Port scanning
   - Service detection
   - NSE script integration

#### Post-Installation:

After successful installation, the following services will be available:

- **Mauritania Eye Dashboard**: http://localhost:5173
- **API Endpoint**: http://localhost:8080/api/status
- **Netdata Monitoring**: http://localhost:19999
- **Ntopng Interface**: http://localhost:3000

#### Configuration Files:

All configuration files are stored in `/opt/mauritania-eye/config/`:
- `zeek-mauritania.zeek` - Zeek configuration
- `suricata-mauritania.yaml` - Suricata configuration
- `kismet_mauritania.conf` - Kismet configuration

#### Log Files:

Centralized logging in `/var/log/mauritania-eye/`:
- Installation logs
- Service status logs
- Error logs

#### Service Management:

```bash
# Check service status
sudo systemctl status mauritania-eye

# Start/stop services
sudo systemctl start mauritania-eye
sudo systemctl stop mauritania-eye

# Enable/disable auto-start
sudo systemctl enable mauritania-eye
sudo systemctl disable mauritania-eye

# View logs
sudo journalctl -u mauritania-eye -f
```

#### API Endpoints:

- `GET /api/status` - Service status information
- `GET /api/data` - Current security data
- `GET /api/alerts` - Recent security alerts
- `GET /api/flows` - Network flow data

#### Troubleshooting:

1. **Permission Issues**:
   ```bash
   sudo chown -R root:root /opt/mauritania-eye
   sudo chmod +x /opt/mauritania-eye/*.py
   ```

2. **Service Failures**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart mauritania-eye
   ```

3. **Network Interface Configuration**:
   Edit configuration files to specify correct network interfaces:
   ```bash
   sudo nano /opt/mauritania-eye/config/zeek-mauritania.zeek
   sudo nano /opt/mauritania-eye/config/suricata-mauritania.yaml
   ```

4. **Firewall Configuration**:
   ```bash
   sudo ufw allow 5173  # Dashboard
   sudo ufw allow 8080  # API
   sudo ufw allow 19999 # Netdata
   ```

#### Security Considerations:

- **Authorization Required**: Only use on networks you own or have explicit permission to monitor
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Access Control**: Restrict access to monitoring interfaces
- **Data Privacy**: Handle captured data according to privacy policies

#### Support:

For issues and support:
1. Check installation logs: `/var/log/mauritania-eye-install.log`
2. Review service logs: `sudo journalctl -u mauritania-eye`
3. Verify network interface configuration
4. Ensure proper permissions and firewall settings

---

**Author**: Mohamed Lemine Ahmed Jidou 🇲🇷  
**Version**: 2.0.0  
**License**: MIT