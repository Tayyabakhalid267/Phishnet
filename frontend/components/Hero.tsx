'use client'

import { motion } from 'framer-motion'

interface HeroProps {
  onScanModeChange: (mode: 'email' | 'url' | 'file' | null) => void
}

export default function Hero({ onScanModeChange }: HeroProps) {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      
      {/* 🔥 STUNNING RED BACKGROUND EFFECTS */}
      <div className="absolute inset-0 bg-blood-gradient">
        {/* Animated red cyber grid */}
        <div className="absolute inset-0 bg-cyber-grid bg-grid opacity-30 animate-pulse-red"></div>
        
        {/* Blood red matrix effect */}
        <div className="absolute inset-0 bg-red-cyber opacity-40"></div>
        
        {/* Floating red particles */}
        <div className="absolute inset-0">
          {Array.from({ length: 25 }).map((_, i) => (
            <motion.div
              key={i}
              className="absolute w-1 h-1 bg-cyber-red-500 rounded-full shadow-neon-red"
              initial={{
                x: Math.random() * (typeof window !== 'undefined' ? window.innerWidth : 1920),
                y: Math.random() * (typeof window !== 'undefined' ? window.innerHeight : 1080),
              }}
              animate={{
                x: Math.random() * (typeof window !== 'undefined' ? window.innerWidth : 1920),
                y: Math.random() * (typeof window !== 'undefined' ? window.innerHeight : 1080),
              }}
              transition={{
                duration: Math.random() * 8 + 12,
                repeat: Infinity,
                ease: "linear"
              }}
            />
          ))}
        </div>
        
        {/* Crimson scan lines */}
        <div className="absolute inset-0">
          <motion.div
            className="absolute top-1/4 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyber-red-500 to-transparent opacity-60"
            animate={{ x: ['-100%', '200%'] }}
            transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
          />
          <motion.div
            className="absolute top-3/4 left-0 w-full h-px bg-gradient-to-r from-transparent via-neon-crimson to-transparent opacity-40"
            animate={{ x: ['100%', '-200%'] }}
            transition={{ duration: 6, repeat: Infinity, ease: 'linear' }}
          />
        </div>
      </div>

      {/* Main Content */}
      <div className="relative z-10 text-center max-w-6xl mx-auto px-4">
        
        {/* Main Heading */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <h1 className="text-6xl md:text-8xl font-bold mb-6 font-cyber animate-glow-intense">
            <span className="text-cyber-red-500 text-glow-red animate-red-glow">🧠 PHISHNET</span>
          </h1>
          
          <h2 className="text-2xl md:text-4xl font-bold mb-8 text-white animate-crimson-breathe">
            <span className="text-neon-red">AI Cybersecurity Suite</span>
          </h2>
          
          <p className="text-xl md:text-2xl text-cyber-red-400 mb-4 font-medium animate-cyber-flicker">
            "Detect, analyze, visualize, and neutralize phishing in real time."
          </p>
          
          <p className="text-lg text-gray-300 mb-12 max-w-3xl mx-auto">
            Advanced AI-powered platform for comprehensive phishing threat detection, 
            analysis, and automated response using cutting-edge machine learning and 
            threat intelligence.
          </p>
        </motion.div>

        {/* Scan Interface */}
        <motion.div
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.3 }}
          className="glass-morphism-red rounded-2xl p-8 mb-12 max-w-4xl mx-auto cyber-border-red animate-blood-pulse"
        >
          <h3 className="text-2xl font-bold mb-6 text-cyber-red-500 text-glow-red animate-pulse-red">
            🔍 Start Threat Analysis
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            {/* Email Analysis */}
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => onScanModeChange('email')}
              className="hologram-red group cursor-pointer text-left p-6 rounded-xl hover:shadow-neon-red transition-all animate-crimson-breathe"
            >
              <div className="text-4xl mb-4 text-center animate-glow-intense">📧</div>
              <h4 className="text-xl font-bold mb-2 text-cyber-red-500 group-hover:text-neon-crimson transition-colors text-glow-red">
                Email Analysis
              </h4>
              <p className="text-gray-300 text-sm mb-4">
                Upload .eml files, paste email content, or analyze headers for phishing indicators
              </p>
              <div className="text-cyber-red-500 font-medium group-hover:text-neon-crimson transition-colors animate-cyber-flicker">
                Click to Scan →
              </div>
            </motion.button>

            {/* URL Scanner */}
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => onScanModeChange('url')}
              className="cyber-card group cursor-pointer text-left"
            >
              <div className="text-4xl mb-4 text-center">🔗</div>
              <h4 className="text-xl font-bold mb-2 text-cyber-green-500 group-hover:text-cyber-blue-500 transition-colors">
                URL Scanner
              </h4>
              <p className="text-gray-300 text-sm mb-4">
                Check suspicious links, analyze domains, and verify SSL certificates
              </p>
              <div className="text-cyber-green-500 font-medium group-hover:text-cyber-blue-500 transition-colors">
                Click to Scan →
              </div>
            </motion.button>

            {/* File Analysis */}
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => onScanModeChange('file')}
              className="cyber-card group cursor-pointer text-left"
            >
              <div className="text-4xl mb-4 text-center">📎</div>
              <h4 className="text-xl font-bold mb-2 text-cyber-green-500 group-hover:text-cyber-blue-500 transition-colors">
                File Analysis
              </h4>
              <p className="text-gray-300 text-sm mb-4">
                Analyze attachments, PDFs, and documents for embedded threats
              </p>
              <div className="text-cyber-green-500 font-medium group-hover:text-cyber-blue-500 transition-colors">
                Click to Scan →
              </div>
            </motion.button>
          </div>
        </motion.div>

        {/* Quick Stats */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-4xl mx-auto"
        >
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-green-500 mb-2">15.7K</div>
            <div className="text-sm text-gray-400">Threats Detected</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-blue-500 mb-2">99.4%</div>
            <div className="text-sm text-gray-400">Detection Rate</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-orange-500 mb-2">2.1s</div>
            <div className="text-sm text-gray-400">Avg Analysis Time</div>
          </div>
          <div className="text-center">
            <div className="text-3xl font-bold text-cyber-purple-500 mb-2">24/7</div>
            <div className="text-sm text-gray-400">AI Protection</div>
          </div>
        </motion.div>
      </div>

      {/* Scanning Animation Overlay */}
      <div className="absolute inset-0 pointer-events-none">
        <motion.div
          className="absolute top-1/2 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-cyber-green-500 to-transparent"
          animate={{
            x: ['-100%', '100%']
          }}
          transition={{
            duration: 3,
            repeat: Infinity,
            ease: 'linear'
          }}
        />
      </div>
    </section>
  )
}