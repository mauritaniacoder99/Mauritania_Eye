import { SecurityAlert, NetworkFlow, VulnerabilityReport, WirelessNetwork, PacketCapture, ThreatIntelligence } from '../types/security';

// Simulated data generators for realistic network security monitoring
export class NetworkSecuritySimulator {
  private static instance: NetworkSecuritySimulator;
  private alerts: SecurityAlert[] = [];
  private flows: NetworkFlow[] = [];
  private vulnerabilities: VulnerabilityReport[] = [];
  private wirelessNetworks: WirelessNetwork[] = [];
  private packets: PacketCapture[] = [];
  private threatIntel: Map<string, ThreatIntelligence> = new Map();

  static getInstance(): NetworkSecuritySimulator {
    if (!NetworkSecuritySimulator.instance) {
      NetworkSecuritySimulator.instance = new NetworkSecuritySimulator();
    }
    return NetworkSecuritySimulator.instance;
  }

  private constructor() {
    this.initializeSimulation();
  }

  private initializeSimulation() {
    // Generate initial data
    this.generateSecurityAlerts(20);
    this.generateNetworkFlows(100);
    this.generateVulnerabilities(15);
    this.generateWirelessNetworks(8);
    this.generatePacketCaptures(50);
    this.generateThreatIntelligence(30);

    // Start real-time simulation
    this.startRealTimeSimulation();
  }

  private startRealTimeSimulation() {
    // Generate new alerts every 10-30 seconds
    setInterval(() => {
      this.generateSecurityAlerts(Math.floor(Math.random() * 3) + 1);
    }, (Math.random() * 20 + 10) * 1000);

    // Generate network flows every 2-5 seconds
    setInterval(() => {
      this.generateNetworkFlows(Math.floor(Math.random() * 5) + 1);
    }, (Math.random() * 3 + 2) * 1000);

    // Generate packet captures every 1-3 seconds
    setInterval(() => {
      this.generatePacketCaptures(Math.floor(Math.random() * 3) + 1);
    }, (Math.random() * 2 + 1) * 1000);

    // Update wireless networks every 30 seconds
    setInterval(() => {
      this.updateWirelessNetworks();
    }, 30000);
  }

  private generateSecurityAlerts(count: number) {
    const alertTypes = [
      { type: 'intrusion', source: 'suricata', titles: ['SQL Injection Attempt', 'Brute Force Attack', 'Port Scan Detected', 'Malicious Payload'] },
      { type: 'malware', source: 'zeek', titles: ['Malware Communication', 'C&C Server Contact', 'Suspicious DNS Query', 'Botnet Activity'] },
      { type: 'anomaly', source: 'zeek', titles: ['Unusual Traffic Pattern', 'Data Exfiltration', 'Abnormal Connection', 'Protocol Anomaly'] },
      { type: 'vulnerability', source: 'nmap', titles: ['Open Port Detected', 'Weak Encryption', 'Default Credentials', 'Unpatched Service'] },
      { type: 'policy_violation', source: 'custom', titles: ['Unauthorized Access', 'Policy Breach', 'Compliance Violation', 'Privilege Escalation'] }
    ];

    const severities: SecurityAlert['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP'];
    const countries = ['United States', 'China', 'Russia', 'Germany', 'United Kingdom', 'France', 'Japan', 'Brazil'];

    for (let i = 0; i < count; i++) {
      const alertType = alertTypes[Math.floor(Math.random() * alertTypes.length)];
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const sourceIP = this.generateRandomIP();
      const destIP = this.generateRandomIP();

      const alert: SecurityAlert = {
        id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        severity,
        type: alertType.type as SecurityAlert['type'],
        source: alertType.source as SecurityAlert['source'],
        title: alertType.titles[Math.floor(Math.random() * alertType.titles.length)],
        description: `Security event detected from ${sourceIP} targeting ${destIP}`,
        sourceIP,
        destinationIP: destIP,
        port: Math.floor(Math.random() * 65535) + 1,
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        geoLocation: {
          country: countries[Math.floor(Math.random() * countries.length)],
          city: 'Unknown',
          lat: Math.random() * 180 - 90,
          lng: Math.random() * 360 - 180
        },
        status: 'active',
        riskScore: Math.floor(Math.random() * 100) + 1,
        evidence: [`Log entry: ${Date.now()}`, `Packet capture available`],
        mitigation: 'Block source IP and monitor for additional activity'
      };

      this.alerts.unshift(alert);
    }

    // Keep only last 100 alerts
    this.alerts = this.alerts.slice(0, 100);
  }

  private generateNetworkFlows(count: number) {
    const protocols = ['TCP', 'UDP', 'ICMP'];
    
    for (let i = 0; i < count; i++) {
      const flow: NetworkFlow = {
        id: `flow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        sourcePort: Math.floor(Math.random() * 65535) + 1,
        destinationPort: Math.floor(Math.random() * 65535) + 1,
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        bytes: Math.floor(Math.random() * 10000) + 100,
        packets: Math.floor(Math.random() * 100) + 1,
        duration: Math.floor(Math.random() * 300) + 1,
        flags: ['SYN', 'ACK', 'FIN'].filter(() => Math.random() > 0.5)
      };

      this.flows.unshift(flow);
    }

    // Keep only last 500 flows
    this.flows = this.flows.slice(0, 500);
  }

  private generateVulnerabilities(count: number) {
    const vulnTypes = [
      'Remote Code Execution',
      'SQL Injection',
      'Cross-Site Scripting',
      'Buffer Overflow',
      'Privilege Escalation',
      'Information Disclosure',
      'Denial of Service',
      'Authentication Bypass'
    ];

    for (let i = 0; i < count; i++) {
      const vuln: VulnerabilityReport = {
        id: `vuln_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        target: this.generateRandomIP(),
        severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)] as VulnerabilityReport['severity'],
        cve: `CVE-2024-${Math.floor(Math.random() * 9999).toString().padStart(4, '0')}`,
        title: vulnTypes[Math.floor(Math.random() * vulnTypes.length)],
        description: 'Vulnerability detected during automated security scan',
        solution: 'Apply security patches and update affected software',
        port: Math.floor(Math.random() * 65535) + 1,
        service: ['HTTP', 'SSH', 'FTP', 'SMTP', 'DNS'][Math.floor(Math.random() * 5)],
        riskScore: Math.floor(Math.random() * 100) + 1,
        exploitable: Math.random() > 0.7
      };

      this.vulnerabilities.unshift(vuln);
    }

    this.vulnerabilities = this.vulnerabilities.slice(0, 50);
  }

  private generateWirelessNetworks(count: number) {
    const ssids = ['Corporate_WiFi', 'Guest_Network', 'IoT_Devices', 'BYOD_Access', 'Hidden_Network', 'Rogue_AP_001'];
    const encryptions = ['WPA3', 'WPA2', 'WEP', 'Open'];

    for (let i = 0; i < count; i++) {
      const network: WirelessNetwork = {
        id: `wifi_${i}`,
        ssid: ssids[Math.floor(Math.random() * ssids.length)],
        bssid: this.generateRandomMAC(),
        channel: Math.floor(Math.random() * 11) + 1,
        frequency: 2400 + Math.floor(Math.random() * 500),
        signalStrength: Math.floor(Math.random() * 100) - 100,
        encryption: encryptions[Math.floor(Math.random() * encryptions.length)],
        isHidden: Math.random() > 0.8,
        isRogue: Math.random() > 0.9,
        clients: Math.floor(Math.random() * 20),
        vendor: ['Cisco', 'Ubiquiti', 'Netgear', 'TP-Link'][Math.floor(Math.random() * 4)],
        lastSeen: new Date()
      };

      this.wirelessNetworks.push(network);
    }
  }

  private generatePacketCaptures(count: number) {
    const protocols = ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS'];
    const infos = ['HTTP GET Request', 'DNS Query', 'TCP Handshake', 'ICMP Ping', 'ARP Request'];

    for (let i = 0; i < count; i++) {
      const packet: PacketCapture = {
        id: `packet_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date(),
        sourceIP: this.generateRandomIP(),
        destinationIP: this.generateRandomIP(),
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        length: Math.floor(Math.random() * 1500) + 64,
        info: infos[Math.floor(Math.random() * infos.length)],
        flags: ['SYN', 'ACK', 'PSH', 'FIN'].filter(() => Math.random() > 0.6)
      };

      this.packets.unshift(packet);
    }

    this.packets = this.packets.slice(0, 200);
  }

  private generateThreatIntelligence(count: number) {
    const reputations: ThreatIntelligence['reputation'][] = ['malicious', 'suspicious', 'clean', 'unknown'];
    const categories = ['malware', 'phishing', 'botnet', 'spam', 'scanner', 'tor'];

    for (let i = 0; i < count; i++) {
      const ip = this.generateRandomIP();
      const intel: ThreatIntelligence = {
        ip,
        reputation: reputations[Math.floor(Math.random() * reputations.length)],
        categories: categories.filter(() => Math.random() > 0.7),
        lastSeen: new Date(Date.now() - Math.random() * 86400000 * 7),
        confidence: Math.floor(Math.random() * 100) + 1,
        sources: ['VirusTotal', 'AbuseIPDB', 'Shodan'].filter(() => Math.random() > 0.5),
        description: 'Threat intelligence data from multiple sources'
      };

      this.threatIntel.set(ip, intel);
    }
  }

  private updateWirelessNetworks() {
    this.wirelessNetworks.forEach(network => {
      network.signalStrength += (Math.random() - 0.5) * 10;
      network.clients += Math.floor((Math.random() - 0.5) * 3);
      network.clients = Math.max(0, network.clients);
      network.lastSeen = new Date();
    });
  }

  private generateRandomIP(): string {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  }

  private generateRandomMAC(): string {
    return Array.from({ length: 6 }, () => 
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join(':');
  }

  // Public methods to access simulated data
  getSecurityAlerts(): SecurityAlert[] {
    return [...this.alerts];
  }

  getNetworkFlows(): NetworkFlow[] {
    return [...this.flows];
  }

  getVulnerabilities(): VulnerabilityReport[] {
    return [...this.vulnerabilities];
  }

  getWirelessNetworks(): WirelessNetwork[] {
    return [...this.wirelessNetworks];
  }

  getPacketCaptures(): PacketCapture[] {
    return [...this.packets];
  }

  getThreatIntelligence(): ThreatIntelligence[] {
    return Array.from(this.threatIntel.values());
  }

  getNetworkStatistics() {
    const now = Date.now();
    const oneHourAgo = now - 3600000;

    const recentAlerts = this.alerts.filter(alert => alert.timestamp.getTime() > oneHourAgo);
    const recentFlows = this.flows.filter(flow => flow.timestamp.getTime() > oneHourAgo);

    return {
      totalAlerts: this.alerts.length,
      criticalAlerts: this.alerts.filter(a => a.severity === 'critical').length,
      activeFlows: recentFlows.length,
      totalBandwidth: recentFlows.reduce((sum, flow) => sum + flow.bytes, 0),
      uniqueIPs: new Set([...this.flows.map(f => f.sourceIP), ...this.flows.map(f => f.destinationIP)]).size,
      topProtocols: this.getTopProtocols(),
      alertsByHour: this.getAlertsByHour(),
      threatLevel: this.calculateThreatLevel()
    };
  }

  private getTopProtocols() {
    const protocolCounts = this.flows.reduce((acc, flow) => {
      acc[flow.protocol] = (acc[flow.protocol] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return Object.entries(protocolCounts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .map(([protocol, count]) => ({ protocol, count }));
  }

  private getAlertsByHour() {
    const hours = Array.from({ length: 24 }, (_, i) => {
      const hour = new Date();
      hour.setHours(hour.getHours() - i, 0, 0, 0);
      return {
        hour: hour.getHours(),
        count: this.alerts.filter(alert => 
          alert.timestamp.getHours() === hour.getHours() &&
          alert.timestamp.getDate() === hour.getDate()
        ).length
      };
    }).reverse();

    return hours;
  }

  private calculateThreatLevel(): 'low' | 'medium' | 'high' | 'critical' {
    const criticalAlerts = this.alerts.filter(a => a.severity === 'critical').length;
    const highAlerts = this.alerts.filter(a => a.severity === 'high').length;

    if (criticalAlerts > 5) return 'critical';
    if (criticalAlerts > 2 || highAlerts > 10) return 'high';
    if (highAlerts > 5) return 'medium';
    return 'low';
  }
}