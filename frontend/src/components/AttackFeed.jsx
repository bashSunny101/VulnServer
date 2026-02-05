import React, { useState, useEffect } from 'react';
import { attacksAPI } from '../services/api';
import { AttackFeedWebSocket } from '../services/api';

/**
 * Live Attack Feed Component
 * Real-time stream of incoming attacks
 */
const AttackFeed = () => {
  const [attacks, setAttacks] = useState([]);
  const [filter, setFilter] = useState('all'); // all, critical, high

  useEffect(() => {
    // Load initial recent attacks
    const loadAttacks = async () => {
      try {
        const response = await attacksAPI.getRecent(50, 0);
        setAttacks(response.data.attacks);
      } catch (error) {
        console.error('Failed to load attacks:', error);
      }
    };

    loadAttacks();

    // WebSocket for real-time updates (optional - implement if backend supports)
    // const ws = new AttackFeedWebSocket(
    //   (newAttack) => {
    //     setAttacks(prev => [newAttack, ...prev].slice(0, 50));
    //   },
    //   (error) => console.error('WebSocket error:', error)
    // );

    // Refresh every 10 seconds
    const interval = setInterval(loadAttacks, 10000);

    return () => {
      clearInterval(interval);
      // ws.close();
    };
  }, []);

  const filteredAttacks = attacks.filter(attack => {
    if (filter === 'critical') return attack.threat_score >= 76;
    if (filter === 'high') return attack.threat_score >= 51;
    return true;
  });

  return (
    <div className="bg-gray-800 rounded-lg p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-semibold">Live Attack Feed</h2>
        
        {/* Filter Buttons */}
        <div className="flex gap-2">
          <button
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded ${
              filter === 'all' ? 'bg-blue-600' : 'bg-gray-700'
            }`}
          >
            All
          </button>
          <button
            onClick={() => setFilter('high')}
            className={`px-3 py-1 rounded ${
              filter === 'high' ? 'bg-orange-600' : 'bg-gray-700'
            }`}
          >
            High+
          </button>
          <button
            onClick={() => setFilter('critical')}
            className={`px-3 py-1 rounded ${
              filter === 'critical' ? 'bg-red-600' : 'bg-gray-700'
            }`}
          >
            Critical
          </button>
        </div>
      </div>

      {/* Attack Feed List */}
      <div className="space-y-2 max-h-96 overflow-y-auto">
        {filteredAttacks.length === 0 ? (
          <div className="text-gray-400 text-center py-8">No attacks found</div>
        ) : (
          filteredAttacks.map((attack, index) => (
            <AttackItem key={attack.id || index} attack={attack} />
          ))
        )}
      </div>
    </div>
  );
};

/**
 * Individual Attack Item
 */
const AttackItem = ({ attack }) => {
  const getThreatColor = (score) => {
    if (score >= 76) return 'border-red-600 bg-red-900/20';
    if (score >= 51) return 'border-orange-600 bg-orange-900/20';
    if (score >= 26) return 'border-yellow-600 bg-yellow-900/20';
    return 'border-green-600 bg-green-900/20';
  };

  const getTimeAgo = (timestamp) => {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now - then;
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  };

  return (
    <div className={`border-l-4 p-3 rounded ${getThreatColor(attack.threat_score)}`}>
      <div className="flex justify-between items-start">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono font-semibold">{attack.src_ip}</span>
            {attack.country && (
              <span className="text-xs text-gray-400">({attack.country})</span>
            )}
            <span className="text-xs px-2 py-0.5 bg-gray-700 rounded">
              {attack.honeypot}
            </span>
          </div>
          <div className="text-sm text-gray-300">{attack.attack_type}</div>
        </div>
        
        <div className="text-right">
          <div className="text-lg font-bold">{attack.threat_score}</div>
          <div className="text-xs text-gray-400">{getTimeAgo(attack.timestamp)}</div>
        </div>
      </div>
    </div>
  );
};

export default AttackFeed;
