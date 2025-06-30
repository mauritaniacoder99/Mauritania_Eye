import React, { useState, useEffect } from 'react';
import { Globe, MapPin, AlertTriangle, Shield } from 'lucide-react';
import { NetworkSecuritySimulator } from '../../services/networkSimulator';

export function ThreatMap() {
  const [simulator] = useState(() => NetworkSecuritySimulator.getInstance());
  const [alerts, setAlerts] = useState(simulator.getSecurityAlerts());
  const [selectedAlert, setSelectedAlert] = useState<any>(null);

  useEffect(() => {
    const interval = setInterval(() => {
      setAlerts(simulator.getSecurityAlerts());
    }, 5000);

    return () => clearInterval(interval);
  }, [simulator]);

  const threatLocations = alerts
    .filter(alert => alert.geoLocation)
    .slice(0, 20)
    .map(alert => ({
      ...alert,
      x: ((alert.geoLocation!.lng + 180) / 360) * 100,
      y: ((90 - alert.geoLocation!.lat) / 180) * 100
    }));

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500 border-red-600';
      case 'high': return 'bg-orange-500 border-orange-600';
      case 'medium': return 'bg-yellow-500 border-yellow-600';
      case 'low': return 'bg-blue-500 border-blue-600';
      default: return 'bg-gray-500 border-gray-600';
    }
  };

  const getSeveritySize = (severity: string) => {
    switch (severity) {
      case 'critical': return 'w-4 h-4';
      case 'high': return 'w-3 h-3';
      case 'medium': return 'w-2 h-2';
      default: return 'w-1.5 h-1.5';
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Globe className="h-6 w-6 text-blue-600" />
              <h3 className="text-lg font-semibold text-gray-900">Global Threat Map</h3>
            </div>
            <div className="flex items-center space-x-4 text-sm text-gray-600">
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                <span>Critical</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-orange-500 rounded-full"></div>
                <span>High</span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-1.5 h-1.5 bg-yellow-500 rounded-full"></div>
                <span>Medium</span>
              </div>
            </div>
          </div>
        </div>

        <div className="p-6">
          <div className="relative bg-gradient-to-b from-blue-50 to-green-50 rounded-lg overflow-hidden" style={{ height: '400px' }}>
            {/* World Map Background */}
            <div className="absolute inset-0 opacity-20">
              <svg viewBox="0 0 1000 500" className="w-full h-full">
                <path d="M150,100 Q200,80 250,100 T350,120 L400,140 Q450,130 500,140 T600,160 L650,180 Q700,170 750,180 T850,200" 
                      stroke="#374151" strokeWidth="2" fill="none" />
                <path d="M100,200 Q150,180 200,200 T300,220 L350,240 Q400,230 450,240 T550,260 L600,280 Q650,270 700,280 T800,300" 
                      stroke="#374151" strokeWidth="2" fill="none" />
                <path d="M200,300 Q250,280 300,300 T400,320 L450,340 Q500,330 550,340 T650,360 L700,380 Q750,370 800,380" 
                      stroke="#374151" strokeWidth="2" fill="none" />
              </svg>
            </div>

            {/* Threat Markers */}
            {threatLocations.map((threat, index) => (
              <div
                key={threat.id}
                className={`absolute transform -translate-x-1/2 -translate-y-1/2 rounded-full border-2 cursor-pointer animate-pulse ${getSeverityColor(threat.severity)} ${getSeveritySize(threat.severity)}`}
                style={{
                  left: `${threat.x}%`,
                  top: `${threat.y}%`,
                  animationDelay: `${index * 0.2}s`
                }}
                onClick={() => setSelectedAlert(threat)}
                title={`${threat.title} - ${threat.geoLocation?.country}`}
              />
            ))}

            {/* Pulse Animation for Active Threats */}
            {threatLocations.filter(t => t.severity === 'critical').map((threat, index) => (
              <div
                key={`pulse-${threat.id}`}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-red-500 animate-ping"
                style={{
                  left: `${threat.x}%`,
                  top: `${threat.y}%`,
                  width: '20px',
                  height: '20px',
                  animationDelay: `${index * 0.5}s`
                }}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Threat Details Panel */}
      {selectedAlert && (
        <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900">Threat Details</h3>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-gray-400 hover:text-gray-600"
              >
                ×
              </button>
            </div>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-medium text-gray-900 mb-2">{selectedAlert.title}</h4>
                <p className="text-sm text-gray-600 mb-4">{selectedAlert.description}</p>
                
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Severity:</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(selectedAlert.severity)} text-white`}>
                      {selectedAlert.severity.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Source IP:</span>
                    <span className="font-mono">{selectedAlert.sourceIP}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Destination IP:</span>
                    <span className="font-mono">{selectedAlert.destinationIP}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Protocol:</span>
                    <span>{selectedAlert.protocol}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Risk Score:</span>
                    <span className="font-medium">{selectedAlert.riskScore}/100</span>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="font-medium text-gray-900 mb-2">Location Information</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-500">Country:</span>
                    <span>{selectedAlert.geoLocation?.country}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Coordinates:</span>
                    <span className="font-mono">
                      {selectedAlert.geoLocation?.lat.toFixed(2)}, {selectedAlert.geoLocation?.lng.toFixed(2)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Detection Source:</span>
                    <span className="uppercase font-medium">{selectedAlert.source}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-500">Timestamp:</span>
                    <span>{selectedAlert.timestamp.toLocaleString()}</span>
                  </div>
                </div>

                <div className="mt-4">
                  <h5 className="font-medium text-gray-900 mb-2">Recommended Actions</h5>
                  <p className="text-sm text-gray-600">{selectedAlert.mitigation}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Live Threat Feed */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Live Threat Feed</h3>
        </div>
        <div className="max-h-64 overflow-y-auto">
          {alerts.slice(0, 10).map((alert) => (
            <div key={alert.id} className="px-6 py-3 border-b border-gray-100 hover:bg-gray-50">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className={`w-2 h-2 rounded-full ${getSeverityColor(alert.severity).split(' ')[0]}`}></div>
                  <div>
                    <span className="text-sm font-medium text-gray-900">{alert.title}</span>
                    <span className="text-xs text-gray-500 ml-2">from {alert.sourceIP}</span>
                  </div>
                </div>
                <span className="text-xs text-gray-500">
                  {alert.timestamp.toLocaleTimeString()}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}