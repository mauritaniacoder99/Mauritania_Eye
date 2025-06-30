import React from 'react';
import { Shield, AlertTriangle, Activity, Globe, Wifi, Bug } from 'lucide-react';
import { NetworkSecuritySimulator } from '../../services/networkSimulator';

export function SecurityOverview() {
  const simulator = NetworkSecuritySimulator.getInstance();
  const stats = simulator.getNetworkStatistics();
  const alerts = simulator.getSecurityAlerts().slice(0, 5);

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default: return 'text-green-600 bg-green-50 border-green-200';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="space-y-6">
      {/* Threat Level Banner */}
      <div className={`p-4 rounded-lg border-2 ${getThreatLevelColor(stats.threatLevel)}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8" />
            <div>
              <h2 className="text-xl font-bold">Current Threat Level: {stats.threatLevel.toUpperCase()}</h2>
              <p className="text-sm opacity-75">Network security status assessment</p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold">{stats.criticalAlerts}</div>
            <div className="text-sm">Critical Alerts</div>
          </div>
        </div>
      </div>

      {/* Security Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Alerts</p>
              <p className="text-3xl font-bold text-gray-900">{stats.totalAlerts}</p>
            </div>
            <AlertTriangle className="h-8 w-8 text-red-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-red-600">
              <span className="font-medium">+{Math.floor(Math.random() * 10) + 1}</span>
              <span className="ml-1">in last hour</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Flows</p>
              <p className="text-3xl font-bold text-gray-900">{stats.activeFlows}</p>
            </div>
            <Activity className="h-8 w-8 text-blue-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-green-600">
              <span className="font-medium">{(stats.totalBandwidth / 1024 / 1024).toFixed(1)} MB</span>
              <span className="ml-1">bandwidth</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Unique IPs</p>
              <p className="text-3xl font-bold text-gray-900">{stats.uniqueIPs}</p>
            </div>
            <Globe className="h-8 w-8 text-purple-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-gray-600">
              <span className="font-medium">Monitored</span>
              <span className="ml-1">endpoints</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Vulnerabilities</p>
              <p className="text-3xl font-bold text-gray-900">{simulator.getVulnerabilities().length}</p>
            </div>
            <Bug className="h-8 w-8 text-orange-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-orange-600">
              <span className="font-medium">{simulator.getVulnerabilities().filter(v => v.exploitable).length}</span>
              <span className="ml-1">exploitable</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Recent Security Alerts</h3>
        </div>
        <div className="divide-y divide-gray-200">
          {alerts.map((alert) => (
            <div key={alert.id} className="px-6 py-4 hover:bg-gray-50">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3">
                  <div className={`w-3 h-3 rounded-full mt-2 ${getSeverityColor(alert.severity)}`}></div>
                  <div className="flex-1">
                    <h4 className="text-sm font-medium text-gray-900">{alert.title}</h4>
                    <p className="text-sm text-gray-600 mt-1">{alert.description}</p>
                    <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                      <span>Source: {alert.source.toUpperCase()}</span>
                      <span>IP: {alert.sourceIP}</span>
                      <span>Protocol: {alert.protocol}</span>
                      <span>Risk: {alert.riskScore}/100</span>
                    </div>
                  </div>
                </div>
                <div className="text-xs text-gray-500">
                  {alert.timestamp.toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Protocol Distribution */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Top Network Protocols</h3>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {stats.topProtocols.map((protocol, index) => (
              <div key={protocol.protocol} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                    <span className="text-xs font-medium text-blue-600">{index + 1}</span>
                  </div>
                  <span className="font-medium text-gray-900">{protocol.protocol}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <div className="w-32 bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-blue-500 h-2 rounded-full" 
                      style={{ width: `${(protocol.count / stats.topProtocols[0].count) * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-sm text-gray-600 w-12 text-right">{protocol.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}