import React from 'react';
import { X, Shield, Globe, Activity, Bug, Wifi, Database, AlertTriangle, BarChart3 } from 'lucide-react';

interface SecuritySidebarProps {
  open: boolean;
  onClose: () => void;
  activeView: string;
  onViewChange: (view: string) => void;
}

const navigation = [
  { name: 'Security Overview', id: 'overview', icon: Shield, description: 'Real-time security dashboard' },
  { name: 'Threat Map', id: 'threats', icon: Globe, description: 'Global threat visualization' },
  { name: 'Network Monitor', id: 'network', icon: Activity, description: 'Live network analysis' },
  { name: 'Vulnerability Scanner', id: 'vulnerabilities', icon: Bug, description: 'Security assessment' },
  { name: 'Intrusion Detection', id: 'ids', icon: AlertTriangle, description: 'IDS/IPS alerts' },
  { name: 'Packet Analysis', id: 'packets', icon: Database, description: 'Deep packet inspection' },
  { name: 'Wireless Security', id: 'wireless', icon: Wifi, description: 'WiFi monitoring' },
  { name: 'Analytics', id: 'analytics', icon: BarChart3, description: 'Security analytics' },
];

export function SecuritySidebar({ open, onClose, activeView, onViewChange }: SecuritySidebarProps) {
  return (
    <>
      <div className={`fixed inset-0 z-50 lg:hidden ${open ? '' : 'hidden'}`}>
        <div className="fixed inset-0 bg-gray-900/80" onClick={onClose} />
        <div className="fixed inset-y-0 left-0 z-50 w-72 bg-gray-900 px-6 pb-4">
          <div className="flex h-16 shrink-0 items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className="h-8 w-8 text-blue-400" />
              <div>
                <h2 className="text-lg font-semibold text-white">Hypervision Mode</h2>
                <p className="text-xs text-gray-400">🌐🧿</p>
              </div>
            </div>
            <button
              type="button"
              className="-m-2.5 p-2.5 text-gray-400 hover:text-white"
              onClick={onClose}
            >
              <span className="sr-only">Close sidebar</span>
              <X className="h-6 w-6" aria-hidden="true" />
            </button>
          </div>
          <nav className="flex flex-1 flex-col mt-6">
            <ul role="list" className="space-y-2">
              {navigation.map((item) => (
                <li key={item.name}>
                  <button
                    onClick={() => {
                      onViewChange(item.id);
                      onClose();
                    }}
                    className={`group flex w-full gap-x-3 rounded-md p-3 text-sm leading-6 font-semibold transition-colors ${
                      activeView === item.id
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-300 hover:text-white hover:bg-gray-800'
                    }`}
                  >
                    <item.icon
                      className={`h-6 w-6 shrink-0 ${
                        activeView === item.id ? 'text-white' : 'text-gray-400 group-hover:text-white'
                      }`}
                      aria-hidden="true"
                    />
                    <div className="text-left">
                      <div>{item.name}</div>
                      <div className="text-xs opacity-75">{item.description}</div>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </div>

      <div className="hidden lg:fixed lg:inset-y-0 lg:z-50 lg:flex lg:w-80 lg:flex-col">
        <div className="flex grow flex-col gap-y-5 overflow-y-auto bg-gray-900 px-6 pb-4">
          <div className="flex h-16 shrink-0 items-center">
            <Shield className="h-8 w-8 text-blue-400" />
            <div className="ml-3">
              <span className="text-xl font-bold text-white">Mauritania Eye</span>
              <div className="text-sm text-blue-400">Hypervision Mode 🌐🧿</div>
              <div className="text-xs text-gray-400">by Mohamed Lemine Ahmed Jidou 🇲🇷</div>
            </div>
          </div>
          <nav className="flex flex-1 flex-col">
            <ul role="list" className="space-y-2">
              {navigation.map((item) => (
                <li key={item.name}>
                  <button
                    onClick={() => onViewChange(item.id)}
                    className={`group flex w-full gap-x-3 rounded-md p-3 text-sm leading-6 font-semibold transition-colors ${
                      activeView === item.id
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-300 hover:text-white hover:bg-gray-800'
                    }`}
                  >
                    <item.icon
                      className={`h-6 w-6 shrink-0 ${
                        activeView === item.id ? 'text-white' : 'text-gray-400 group-hover:text-white'
                      }`}
                      aria-hidden="true"
                    />
                    <div className="text-left">
                      <div>{item.name}</div>
                      <div className="text-xs opacity-75">{item.description}</div>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          </nav>

          {/* System Status */}
          <div className="mt-auto">
            <div className="bg-gray-800 rounded-lg p-4">
              <h4 className="text-sm font-medium text-white mb-2">System Status</h4>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-400">Zeek</span>
                  <span className="text-green-400">●  Active</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Suricata</span>
                  <span className="text-green-400">●  Active</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Wireshark</span>
                  <span className="text-green-400">●  Capturing</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-400">Kismet</span>
                  <span className="text-green-400">●  Monitoring</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}