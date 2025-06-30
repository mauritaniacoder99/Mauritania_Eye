export interface SecurityAlert {
  id: string;
  timestamp: Date;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type: 'intrusion' | 'malware' | 'anomaly' | 'vulnerability' | 'policy_violation';
  source: 'zeek' | 'suricata' | 'wireshark' | 'nmap' | 'kismet' | 'custom';
  title: string;
  description: string;
  sourceIP: string;
  destinationIP: string;
  port?: number;
  protocol: string;
  geoLocation?: {
    country: string;
    city: string;
    lat: number;
    lng: number;
  };
  status: 'active' | 'investigating' | 'resolved' | 'false_positive';
  riskScore: number;
  evidence?: string[];
  mitigation?: string;
}

export interface NetworkFlow {
  id: string;
  timestamp: Date;
  sourceIP: string;
  destinationIP: string;
  sourcePort: number;
  destinationPort: number;
  protocol: string;
  bytes: number;
  packets: number;
  duration: number;
  flags: string[];
  geoLocation?: {
    source: { country: string; city: string; lat: number; lng: number };
    destination: { country: string; city: string; lat: number; lng: number };
  };
}

export interface VulnerabilityReport {
  id: string;
  timestamp: Date;
  target: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cve?: string;
  title: string;
  description: string;
  solution: string;
  port?: number;
  service?: string;
  riskScore: number;
  exploitable: boolean;
}

export interface WirelessNetwork {
  id: string;
  ssid: string;
  bssid: string;
  channel: number;
  frequency: number;
  signalStrength: number;
  encryption: string;
  isHidden: boolean;
  isRogue: boolean;
  clients: number;
  vendor?: string;
  lastSeen: Date;
}

export interface PacketCapture {
  id: string;
  timestamp: Date;
  sourceIP: string;
  destinationIP: string;
  protocol: string;
  length: number;
  info: string;
  payload?: string;
  flags: string[];
}

export interface ThreatIntelligence {
  ip: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  categories: string[];
  lastSeen: Date;
  confidence: number;
  sources: string[];
  description?: string;
}