import React from 'react';
import { Menu, Download, Settings, AlertTriangle, Shield } from 'lucide-react';
import { NetworkSecuritySimulator } from '../../services/networkSimulator';

interface SecurityHeaderProps {
  onMenuClick: () => void;
}

export function SecurityHeader({ onMenuClick }: SecurityHeaderProps) {
  const simulator = NetworkSecuritySimulator.getInstance();
  const stats = simulator.getNetworkStatistics();

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical': return 'text-red-600 bg-red-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-green-600 bg-green-100';
    }
  };

  return (
    <div className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-gray-200 bg-white px-4 shadow-sm sm:gap-x-6 sm:px-6 lg:px-8">
      <button
        type="button"
        className="-m-2.5 p-2.5 text-gray-700 lg:hidden"
        onClick={onMenuClick}
      >
        <span className="sr-only">Open sidebar</span>
        <Menu className="h-6 w-6" aria-hidden="true" />
      </button>

      <div className="h-6 w-px bg-gray-200 lg:hidden" aria-hidden="true" />

      <div className="flex flex-1 justify-between items-center">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <Shield className="h-6 w-6 text-blue-600" />
            <h1 className="text-xl font-bold text-gray-900">
              Mauritania Eye - Hypervision Mode
            </h1>
          </div>
          
          {/* Threat Level Indicator */}
          <div className={`px-3 py-1 rounded-full text-sm font-medium ${getThreatLevelColor(stats.threatLevel)}`}>
            <div className="flex items-center space-x-1">
              <AlertTriangle className="h-4 w-4" />
              <span>Threat Level: {stats.threatLevel.toUpperCase()}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-x-4 lg:gap-x-6">
          {/* Quick Stats */}
          <div className="hidden md:flex items-center space-x-6 text-sm text-gray-600">
            <div className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
              <span>{stats.criticalAlerts} Critical</span>
            </div>
            <div className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-blue-500 rounded-full"></div>
              <span>{stats.activeFlows} Flows</span>
            </div>
            <div className="flex items-center space-x-1">
              <div className="w-2 h-2 bg-green-500 rounded-full"></div>
              <span>{(stats.totalBandwidth / 1024 / 1024).toFixed(1)} MB</span>
            </div>
          </div>

          <button
            type="button"
            className="flex items-center gap-2 rounded-md bg-blue-600 px-3 py-1.5 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export Report
          </button>

          <button
            type="button"
            className="-m-1.5 flex items-center p-1.5 text-gray-400 hover:text-gray-500 transition-colors"
          >
            <Settings className="h-6 w-6" />
            <span className="sr-only">Settings</span>
          </button>
        </div>
      </div>
    </div>
  );
}