import React, { useState, useEffect } from 'react';
import { dashboardAPI, attacksAPI } from '../services/api';
import { 
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer 
} from 'recharts';

/**
 * Main Dashboard Component
 * Displays real-time threat intelligence overview
 */
const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [topAttackers, setTopAttackers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch dashboard data
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        
        // Fetch all data in parallel
        const [statsRes, timelineRes, attackersRes] = await Promise.all([
          dashboardAPI.getStats(),
          dashboardAPI.getTimeline(24),
          attacksAPI.getTopAttackers(10, 24)
        ]);
        
        setStats(statsRes.data);
        setTimeline(timelineRes.data.timeline);
        setTopAttackers(attackersRes.data.top_attackers);
        setError(null);
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
        setError('Failed to load dashboard data. Please try again.');
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    
    // Refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl">Loading dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-red-600">{error}</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      {/* Header */}
      <header className="mb-8">
        <h1 className="text-4xl font-bold mb-2">🛡️ HoneyNet Intelligence Platform</h1>
        <p className="text-gray-400">Real-time Threat Detection & Analysis</p>
      </header>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          title="Total Attacks (24h)"
          value={stats?.total_attacks_24h || 0}
          icon="🎯"
          color="bg-blue-600"
        />
        <StatCard
          title="Unique Attackers"
          value={stats?.unique_ips_24h || 0}
          icon="👤"
          color="bg-purple-600"
        />
        <StatCard
          title="Critical Threats"
          value={stats?.critical_threats || 0}
          icon="🚨"
          color="bg-red-600"
        />
        <StatCard
          title="Avg Threat Score"
          value={stats?.avg_threat_score?.toFixed(1) || 0}
          icon="📊"
          color="bg-orange-600"
        />
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Attack Timeline */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Attack Timeline (24h)</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={timeline}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis 
                dataKey="timestamp" 
                stroke="#9CA3AF"
                tickFormatter={(value) => new Date(value).getHours() + ':00'}
              />
              <YAxis stroke="#9CA3AF" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1F2937', border: 'none' }}
                labelStyle={{ color: '#9CA3AF' }}
              />
              <Legend />
              <Line 
                type="monotone" 
                dataKey="count" 
                stroke="#3B82F6" 
                strokeWidth={2}
                name="Attack Count"
              />
              <Line 
                type="monotone" 
                dataKey="avg_threat_score" 
                stroke="#EF4444" 
                strokeWidth={2}
                name="Avg Threat Score"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Top Countries */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4">Top Attacking Countries</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats?.top_countries || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="country" stroke="#9CA3AF" />
              <YAxis stroke="#9CA3AF" />
              <Tooltip 
                contentStyle={{ backgroundColor: '#1F2937', border: 'none' }}
              />
              <Bar dataKey="count" fill="#8B5CF6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Attackers Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-xl font-semibold mb-4">Top Attackers (24h)</h2>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4">Rank</th>
                <th className="text-left py-3 px-4">IP Address</th>
                <th className="text-left py-3 px-4">Country</th>
                <th className="text-left py-3 px-4">Attack Count</th>
                <th className="text-left py-3 px-4">Avg Threat Score</th>
                <th className="text-left py-3 px-4">Severity</th>
              </tr>
            </thead>
            <tbody>
              {topAttackers.map((attacker, index) => (
                <tr key={attacker.ip} className="border-b border-gray-700 hover:bg-gray-700">
                  <td className="py-3 px-4">#{index + 1}</td>
                  <td className="py-3 px-4 font-mono">{attacker.ip}</td>
                  <td className="py-3 px-4">{attacker.country}</td>
                  <td className="py-3 px-4">{attacker.attack_count}</td>
                  <td className="py-3 px-4">{attacker.avg_threat_score}</td>
                  <td className="py-3 px-4">
                    <ThreatBadge score={attacker.avg_threat_score} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

/**
 * Stat Card Component
 */
const StatCard = ({ title, value, icon, color }) => (
  <div className={`${color} rounded-lg p-6 shadow-lg`}>
    <div className="flex items-center justify-between">
      <div>
        <p className="text-sm opacity-80 mb-1">{title}</p>
        <p className="text-3xl font-bold">{value.toLocaleString()}</p>
      </div>
      <div className="text-4xl opacity-80">{icon}</div>
    </div>
  </div>
);

/**
 * Threat Badge Component
 */
const ThreatBadge = ({ score }) => {
  let color, label;
  
  if (score >= 76) {
    color = 'bg-red-600';
    label = 'CRITICAL';
  } else if (score >= 51) {
    color = 'bg-orange-600';
    label = 'HIGH';
  } else if (score >= 26) {
    color = 'bg-yellow-600';
    label = 'MEDIUM';
  } else {
    color = 'bg-green-600';
    label = 'LOW';
  }
  
  return (
    <span className={`${color} px-3 py-1 rounded-full text-xs font-semibold`}>
      {label}
    </span>
  );
};

export default Dashboard;
