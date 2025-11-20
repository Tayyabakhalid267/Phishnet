'use client'

import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'

interface ThreatData {
  id: string
  type: 'phishing' | 'malware' | 'suspicious' | 'safe'
  location: { lat: number, lng: number }
  intensity: number
  timestamp: Date
}

export default function ThreatVisualization() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [threats, setThreats] = useState<ThreatData[]>([])
  const [activeThreats, setActiveThreats] = useState(0)
  const [totalScanned, setTotalScanned] = useState(0)

  // 🔴 Generate realistic threat data
  useEffect(() => {
    const generateThreat = (): ThreatData => ({
      id: Math.random().toString(36).substr(2, 9),
      type: ['phishing', 'malware', 'suspicious', 'safe'][Math.floor(Math.random() * 4)] as ThreatData['type'],
      location: {
        lat: (Math.random() - 0.5) * 180,
        lng: (Math.random() - 0.5) * 360
      },
      intensity: Math.random(),
      timestamp: new Date()
    })

    const interval = setInterval(() => {
      const newThreat = generateThreat()
      setThreats(prev => [...prev.slice(-50), newThreat])
      setTotalScanned(prev => prev + 1)
      setActiveThreats(prev => newThreat.type !== 'safe' ? prev + 1 : Math.max(0, prev - 1))
    }, 2000)

    return () => clearInterval(interval)
  }, [])

  // 🎨 Canvas drawing for threat map
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const animate = () => {
      // Clear canvas with dark red background
      ctx.fillStyle = '#0f0000'
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      // Draw grid
      ctx.strokeStyle = 'rgba(255, 0, 64, 0.1)'
      ctx.lineWidth = 1
      for (let i = 0; i < canvas.width; i += 20) {
        ctx.beginPath()
        ctx.moveTo(i, 0)
        ctx.lineTo(i, canvas.height)
        ctx.stroke()
      }
      for (let i = 0; i < canvas.height; i += 20) {
        ctx.beginPath()
        ctx.moveTo(0, i)
        ctx.lineTo(canvas.width, i)
        ctx.stroke()
      }

      // Draw threats
      threats.forEach((threat, index) => {
        const x = (threat.location.lng + 180) / 360 * canvas.width
        const y = (90 - threat.location.lat) / 180 * canvas.height
        const size = threat.intensity * 10 + 5
        const alpha = Math.max(0, 1 - (Date.now() - threat.timestamp.getTime()) / 10000)

        let color = ''
        switch (threat.type) {
          case 'phishing': color = `rgba(255, 0, 64, ${alpha})`; break
          case 'malware': color = `rgba(220, 20, 60, ${alpha})`; break
          case 'suspicious': color = `rgba(255, 69, 0, ${alpha})`; break
          case 'safe': color = `rgba(0, 255, 136, ${alpha * 0.5})`; break
        }

        // Pulsing threat dots
        ctx.beginPath()
        ctx.arc(x, y, size * (1 + Math.sin(Date.now() * 0.01 + index) * 0.3), 0, Math.PI * 2)
        ctx.fillStyle = color
        ctx.fill()

        // Glow effect
        ctx.beginPath()
        ctx.arc(x, y, size * 2, 0, Math.PI * 2)
        ctx.fillStyle = color.replace(/[^,]+(?=\))/, '0.1')
        ctx.fill()
      })

      requestAnimationFrame(animate)
    }

    animate()
  }, [threats])

  return (
    <div className="relative w-full max-w-6xl mx-auto">
      
      {/* 📊 Real-time Stats Dashboard */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8"
      >
        <div className="glass-morphism-red p-4 rounded-xl cyber-border-red">
          <div className="text-2xl font-bold text-cyber-red-500 animate-red-glow">{activeThreats}</div>
          <div className="text-sm text-gray-400">Active Threats</div>
        </div>
        <div className="glass-morphism-red p-4 rounded-xl cyber-border-red">
          <div className="text-2xl font-bold text-neon-crimson animate-pulse-red">{totalScanned}</div>
          <div className="text-sm text-gray-400">Total Scanned</div>
        </div>
        <div className="glass-morphism-red p-4 rounded-xl cyber-border-red">
          <div className="text-2xl font-bold text-cyber-red-400 animate-crimson-breathe">99.4%</div>
          <div className="text-sm text-gray-400">Detection Rate</div>
        </div>
        <div className="glass-morphism-red p-4 rounded-xl cyber-border-red">
          <div className="text-2xl font-bold text-neon-red animate-cyber-flicker">2.1s</div>
          <div className="text-sm text-gray-400">Avg Response</div>
        </div>
      </motion.div>

      {/* 🌍 Global Threat Map */}
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8 }}
        className="glass-morphism-red rounded-2xl p-6 cyber-border-red relative overflow-hidden"
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-2xl font-bold text-cyber-red-500 text-glow-red">
            🌐 Live Threat Map
          </h3>
          <div className="flex items-center space-x-4 text-sm">
            <div className="flex items-center">
              <div className="w-3 h-3 bg-cyber-red-500 rounded-full mr-2 animate-pulse-red"></div>
              <span className="text-gray-300">Phishing</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 bg-neon-crimson rounded-full mr-2 animate-glow-intense"></div>
              <span className="text-gray-300">Malware</span>
            </div>
            <div className="flex items-center">
              <div className="w-3 h-3 bg-cyber-red-400 rounded-full mr-2 animate-crimson-breathe"></div>
              <span className="text-gray-300">Suspicious</span>
            </div>
          </div>
        </div>

        <canvas
          ref={canvasRef}
          width={800}
          height={400}
          className="w-full h-96 rounded-xl bg-cyber-darker border border-cyber-red-500/30"
        />

        {/* Scanner overlay effect */}
        <motion.div
          className="absolute top-20 left-6 right-6 h-px bg-gradient-to-r from-transparent via-cyber-red-500 to-transparent"
          animate={{ y: [0, 380, 0] }}
          transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
        />
      </motion.div>

      {/* 📈 Threat Intelligence Feed */}
      <motion.div
        initial={{ opacity: 0, x: -50 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.8, delay: 0.3 }}
        className="mt-8 glass-morphism-red rounded-2xl p-6 cyber-border-red"
      >
        <h3 className="text-xl font-bold text-cyber-red-500 mb-4 text-glow-red">
          🚨 Latest Threat Detections
        </h3>
        <div className="space-y-3 max-h-60 overflow-y-auto">
          {threats.slice(-5).reverse().map((threat, index) => (
            <motion.div
              key={threat.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="flex items-center justify-between p-3 bg-cyber-blood/20 rounded-lg border border-cyber-red-500/20 hover:bg-cyber-blood/30 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <div className={`w-2 h-2 rounded-full ${
                  threat.type === 'phishing' ? 'bg-cyber-red-500 animate-pulse-red' :
                  threat.type === 'malware' ? 'bg-neon-crimson animate-glow-intense' :
                  threat.type === 'suspicious' ? 'bg-cyber-red-400 animate-crimson-breathe' :
                  'bg-alert-info animate-cyber-flicker'
                }`}></div>
                <span className="text-sm text-gray-300 font-mono">
                  {threat.type.toUpperCase()}
                </span>
                <span className="text-xs text-gray-500">
                  {threat.location.lat.toFixed(2)}, {threat.location.lng.toFixed(2)}
                </span>
              </div>
              <div className="text-xs text-gray-400">
                {threat.timestamp.toLocaleTimeString()}
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  )
}