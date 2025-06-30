import React, { useState } from 'react';
import { SecuritySidebar } from './components/layout/SecuritySidebar';
import { SecurityHeader } from './components/layout/SecurityHeader';
import { SecurityOverview } from './components/security/SecurityOverview';
import { ThreatMap } from './components/security/ThreatMap';
import { NetworkMonitor } from './components/security/NetworkMonitor';
import { VulnerabilityScanner } from './components/security/VulnerabilityScanner';

function App() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeView, setActiveView] = useState('overview');

  const renderActiveView = () => {
    switch (activeView) {
      case 'overview':
        return <SecurityOverview />;
      case 'threats':
        return <ThreatMap />;
      case 'network':
        return <NetworkMonitor />;
      case 'vulnerabilities':
        return <VulnerabilityScanner />;
      case 'ids':
        return <SecurityOverview />; // Placeholder for IDS view
      case 'packets':
        return <NetworkMonitor />; // Placeholder for packet analysis
      case 'wireless':
        return <NetworkMonitor />; // Placeholder for wireless security
      case 'analytics':
        return <SecurityOverview />; // Placeholder for analytics
      default:
        return <SecurityOverview />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <SecuritySidebar 
        open={sidebarOpen} 
        onClose={() => setSidebarOpen(false)}
        activeView={activeView}
        onViewChange={setActiveView}
      />
      
      <div className="lg:pl-80">
        <SecurityHeader onMenuClick={() => setSidebarOpen(true)} />
        <main className="py-6">
          <div className="px-4 sm:px-6 lg:px-8">
            {renderActiveView()}
          </div>
        </main>
      </div>
    </div>
  );
}

export default App;