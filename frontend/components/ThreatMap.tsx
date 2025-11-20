'use client'

export default function ThreatMap() {
  return (
    <div className="cyber-card">
      <div className="text-center py-20">
        <div className="text-8xl mb-6">🌍</div>
        <h3 className="text-3xl font-bold mb-4 text-cyber-blue-500">
          Global Threat Map
        </h3>
        <p className="text-lg text-gray-300 mb-6 max-w-2xl mx-auto">
          Interactive 3D visualization of real-time phishing attacks and threat intelligence 
          from around the world. This advanced WebGL-powered map will show attack patterns, 
          threat actor locations, and campaign distributions.
        </p>
        <div className="inline-block px-6 py-3 bg-cyber-blue-500/10 border border-cyber-blue-500/30 rounded-lg">
          <span className="text-cyber-blue-500 font-medium">
            🚧 3D Globe Implementation Coming Soon
          </span>
        </div>
      </div>
    </div>
  )
}