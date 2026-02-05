import React from 'react';
import Dashboard from './components/Dashboard';
import GeoMap from './components/GeoMap';
import AttackFeed from './components/AttackFeed';
import './index.css';

/**
 * Main App Component
 * Entry point for the React application
 */
function App() {
  return (
    <div className="App">
      {/* Main Dashboard */}
      <Dashboard />
      
      {/* Additional Sections */}
      <div className="p-6 space-y-6">
        {/* Geographic Map */}
        <GeoMap />
        
        {/* Live Attack Feed */}
        <AttackFeed />
      </div>
    </div>
  );
}

export default App;
