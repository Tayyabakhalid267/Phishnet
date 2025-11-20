'use client'

export default function LiveStats() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      
      <div className="cyber-card text-center">
        <div className="text-3xl mb-2">🛡️</div>
        <div className="text-2xl font-bold text-cyber-green-500 mb-1">15,742</div>
        <div className="text-sm text-gray-400">Threats Blocked Today</div>
        <div className="text-xs text-cyber-green-500 mt-1">↗ +23% from yesterday</div>
      </div>

      <div className="cyber-card text-center">
        <div className="text-3xl mb-2">🎯</div>
        <div className="text-2xl font-bold text-cyber-red-500 mb-1">156</div>
        <div className="text-sm text-gray-400">Active Campaigns</div>
        <div className="text-xs text-cyber-red-500 mt-1">↗ +5 new this hour</div>
      </div>

      <div className="cyber-card text-center">
        <div className="text-3xl mb-2">📊</div>
        <div className="text-2xl font-bold text-cyber-blue-500 mb-1">99.4%</div>
        <div className="text-sm text-gray-400">Detection Accuracy</div>
        <div className="text-xs text-cyber-green-500 mt-1">↗ +0.2% this week</div>
      </div>

      <div className="cyber-card text-center">
        <div className="text-3xl mb-2">⚡</div>
        <div className="text-2xl font-bold text-cyber-orange-500 mb-1">2.1s</div>
        <div className="text-sm text-gray-400">Avg Response Time</div>
        <div className="text-xs text-cyber-green-500 mt-1">↘ -0.3s improved</div>
      </div>
    </div>
  )
}