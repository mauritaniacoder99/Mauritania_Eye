import React, { useState, useEffect } from 'react';
import { Activity, Wifi, Monitor, Database, Network } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { NetworkSecuritySimulator } from '../../services/networkSimulator';

export function NetworkMonitor() {
  const [simulator] = useState(() => NetworkSecuritySimulator.getInstance());
  const [flows, setFlows] = useState(simulator.getNetworkFlows());
  const [packets, setPackets] = useState(simulator.getPacketCaptures());
  const [wirelessNetworks, setWirelessNetworks] = useState(simulator.getWirelessNetworks());

  useEffect(() => {
    const interval = setInterval(() => {
      setFlows(simulator.getNetworkFlows());
      setPackets(simulator.getPacketCaptures());
      setWirelessNetworks(simulator.getWirelessNetworks());
    }, 3000);

    return () => clearInterval(interval);
  }, [simulator]);

  // Process data for charts
  const trafficData = flows.slice(0, 20).map((flow, index) => ({
    time: `${index}s`,
    bytes: flow.bytes,
    packets: flow.packets,
    protocol: flow.protocol
  }));

  const protocolData = flows.reduce((acc, flow) => {
    acc[flow.protocol] = (acc[flow.protocol] || 0) + flow.bytes;
    return acc;
  }, {} as Record<string, number>);

  const protocolChartData = Object.entries(protocolData).map(([protocol, bytes]) => ({
    protocol,
    bytes,
    percentage: ((bytes / Object.values(protocolData).reduce((a, b) => a + b, 0)) * 100).toFixed(1)
  }));

  const COLORS = ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];

  return (
    <div className="space-y-6">
      {/* Network Statistics Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Active Flows</p>
              <p className="text-3xl font-bold text-gray-900">{flows.length}</p>
            </div>
            <Activity className="h-8 w-8 text-blue-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-blue-600">
              <span className="font-medium">Real-time</span>
              <span className="ml-1">monitoring</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Packet Captures</p>
              <p className="text-3xl font-bold text-gray-900">{packets.length}</p>
            </div>
            <Database className="h-8 w-8 text-green-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-green-600">
              <span className="font-medium">Deep</span>
              <span className="ml-1">inspection</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Wireless APs</p>
              <p className="text-3xl font-bold text-gray-900">{wirelessNetworks.length}</p>
            </div>
            <Wifi className="h-8 w-8 text-purple-500" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm text-red-600">
              <span className="font-medium">{wirelessNetworks.filter(w => w.isRogue).length}</span>
              <span className="ml-1">rogue APs</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Bandwidth</p>
              <p className="text-3xl font-bold text-gray-900">
                {(flows.reduce((sum, flow) => sum + flow.bytes, 0) / 1024 / 1024).toFixed(1)}
              </p>
              <p className="text-sm text-gray-500">MB</p>
            </div>
            <Network className="h-8 w-8 text-orange-500" />
          </div>
        </div>
      </div>

      {/* Network Traffic Chart */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Real-time Network Traffic</h3>
        </div>
        <div className="p-6">
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="bytes" 
                stroke="#2563eb" 
                strokeWidth={2}
                name="Bytes"
              />
              <Line 
                type="monotone" 
                dataKey="packets" 
                stroke="#10b981" 
                strokeWidth={2}
                name="Packets"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol Distribution */}
        <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Protocol Distribution</h3>
          </div>
          <div className="p-6">
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={protocolChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ protocol, percentage }) => `${protocol} ${percentage}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="bytes"
                >
                  {protocolChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(value: any) => [(value / 1024).toFixed(1) + ' KB', 'Bytes']} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Wireless Networks */}
        <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900">Wireless Networks (Kismet)</h3>
          </div>
          <div className="max-h-64 overflow-y-auto">
            {wirelessNetworks.map((network) => (
              <div key={network.id} className="px-6 py-3 border-b border-gray-100">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <Wifi className={`h-4 w-4 ${network.isRogue ? 'text-red-500' : 'text-green-500'}`} />
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-gray-900">
                          {network.isHidden ? '[Hidden Network]' : network.ssid}
                        </span>
                        {network.isRogue && (
                          <span className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">ROGUE</span>
                        )}
                      </div>
                      <div className="text-xs text-gray-500">
                        {network.bssid} • Ch {network.channel} • {network.encryption}
                      </div>
                    </div>
                  </div>
                  <div className="text-right text-sm">
                    <div className="text-gray-900">{network.signalStrength} dBm</div>
                    <div className="text-gray-500">{network.clients} clients</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Packet Capture Table */}
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Live Packet Capture (Wireshark/Tshark)</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Destination</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Protocol</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Length</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Info</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {packets.slice(0, 10).map((packet) => (
                <tr key={packet.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">
                    {packet.timestamp.toLocaleTimeString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">
                    {packet.sourceIP}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 font-mono">
                    {packet.destinationIP}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    <span className="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">
                      {packet.protocol}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {packet.length} bytes
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-900">
                    {packet.info}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}