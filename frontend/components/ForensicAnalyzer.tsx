'use client'

import { useState, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface EmailAnalysis {
  id: string
  sender: string
  subject: string
  timestamp: string
  threatScore: number
  spfStatus: 'PASS' | 'FAIL' | 'WARN'
  dkimStatus: 'PASS' | 'FAIL' | 'WARN'
  dmarcStatus: 'PASS' | 'FAIL' | 'WARN'
  suspiciousIndicators: string[]
  rawHeaders: string
  content: string
}

export default function ForensicAnalyzer() {
  const [activeTab, setActiveTab] = useState<'upload' | 'analyze' | 'results'>('upload')
  const [emailData, setEmailData] = useState<string>('')
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // 🔍 Simulate AI analysis
  const analyzeEmail = async () => {
    setIsAnalyzing(true)
    setActiveTab('analyze')
    
    // Simulate AI processing
    await new Promise(resolve => setTimeout(resolve, 3000))
    
    const mockAnalysis: EmailAnalysis = {
      id: Date.now().toString(),
      sender: 'security-update@paypaI-verification.com',
      subject: 'Urgent: Verify Your Account Within 24 Hours',
      timestamp: new Date().toISOString(),
      threatScore: 95,
      spfStatus: 'FAIL',
      dkimStatus: 'FAIL', 
      dmarcStatus: 'FAIL',
      suspiciousIndicators: [
        'Punycode domain detected (paypaI vs paypal)',
        'Urgency tactics in subject line',
        'Sender domain age < 30 days',
        'No DKIM signature found',
        'Suspicious attachment detected'
      ],
      rawHeaders: `From: security-update@paypaI-verification.com
To: victim@company.com
Subject: Urgent: Verify Your Account Within 24 Hours
Date: ${new Date().toUTCString()}
Message-ID: <${Date.now()}@paypaI-verification.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Return-Path: <bounce@suspicious-domain.net>`,
      content: emailData
    }
    
    setAnalysis(mockAnalysis)
    setIsAnalyzing(false)
    setActiveTab('results')
  }

  return (
    <div className="w-full max-w-6xl mx-auto">
      
      {/* 🎯 Analysis Tabs */}
      <div className="flex space-x-1 mb-8 glass-morphism-red rounded-xl p-2 cyber-border-red">
        {(['upload', 'analyze', 'results'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            disabled={tab === 'results' && !analysis}
            className={`flex-1 py-3 px-6 rounded-lg font-medium transition-all ${
              activeTab === tab
                ? 'bg-cyber-red-500 text-white shadow-neon-red animate-pulse-red'
                : 'text-gray-400 hover:text-cyber-red-500 hover:bg-cyber-blood/20'
            }`}
          >
            {tab === 'upload' && '📤 Upload'}
            {tab === 'analyze' && '🧠 Analyze'} 
            {tab === 'results' && '📊 Results'}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        
        {/* 📤 UPLOAD TAB */}
        {activeTab === 'upload' && (
          <motion.div
            key="upload"
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 50 }}
            className="glass-morphism-red rounded-2xl p-8 cyber-border-red"
          >
            <h2 className="text-3xl font-bold text-cyber-red-500 mb-6 text-glow-red animate-red-glow">
              🕵️ Email Forensic Analyzer
            </h2>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              
              {/* File Upload */}
              <div className="space-y-4">
                <h3 className="text-xl font-bold text-neon-crimson">Upload Email File</h3>
                <div
                  onClick={() => fileInputRef.current?.click()}
                  className="border-2 border-dashed border-cyber-red-500/50 rounded-xl p-8 text-center cursor-pointer hover:border-cyber-red-500 hover:bg-cyber-blood/10 transition-all animate-blood-pulse"
                >
                  <div className="text-6xl mb-4 animate-glow-intense">📧</div>
                  <p className="text-gray-300 mb-2">Drop .eml, .msg files here</p>
                  <p className="text-sm text-gray-500">Or click to browse</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".eml,.msg,.txt"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) {
                        const reader = new FileReader()
                        reader.onload = (e) => setEmailData(e.target?.result as string)
                        reader.readAsText(file)
                      }
                    }}
                  />
                </div>
              </div>

              {/* Paste Content */}
              <div className="space-y-4">
                <h3 className="text-xl font-bold text-neon-crimson">Paste Email Content</h3>
                <textarea
                  value={emailData}
                  onChange={(e) => setEmailData(e.target.value)}
                  placeholder="Paste suspicious email content, headers, or raw message here..."
                  className="w-full h-64 bg-cyber-darker border border-cyber-red-500/30 rounded-xl p-4 text-gray-300 font-mono text-sm focus:border-cyber-red-500 focus:ring-2 focus:ring-cyber-red-500/20 resize-none"
                />
              </div>
            </div>

            {emailData && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-8 text-center"
              >
                <button
                  onClick={analyzeEmail}
                  className="bg-cyber-red-500 hover:bg-neon-crimson text-white font-bold py-4 px-8 rounded-xl shadow-neon-red hover:shadow-danger-intense transition-all animate-glow-intense"
                >
                  🚀 Start AI Analysis
                </button>
              </motion.div>
            )}
          </motion.div>
        )}

        {/* 🧠 ANALYZE TAB */}
        {activeTab === 'analyze' && isAnalyzing && (
          <motion.div
            key="analyze"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 1.1 }}
            className="glass-morphism-red rounded-2xl p-8 cyber-border-red text-center"
          >
            <h2 className="text-3xl font-bold text-cyber-red-500 mb-8 text-glow-red">
              🧠 AI Analysis In Progress
            </h2>
            
            <div className="relative w-40 h-40 mx-auto mb-8">
              <motion.div
                className="absolute inset-0 border-4 border-cyber-red-500 rounded-full"
                animate={{ rotate: 360 }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              />
              <motion.div
                className="absolute inset-2 border-4 border-neon-crimson rounded-full border-t-transparent"
                animate={{ rotate: -360 }}
                transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
              />
              <div className="absolute inset-0 flex items-center justify-center text-4xl animate-pulse-red">
                🔍
              </div>
            </div>

            <div className="space-y-4">
              <div className="text-lg text-cyber-red-400 animate-cyber-flicker">
                Scanning email headers and content...
              </div>
              <div className="text-lg text-neon-crimson animate-crimson-breathe">
                Analyzing threat indicators...
              </div>
              <div className="text-lg text-cyber-red-500 animate-glow-intense">
                Cross-referencing threat intelligence...
              </div>
            </div>
          </motion.div>
        )}

        {/* 📊 RESULTS TAB */}
        {activeTab === 'results' && analysis && (
          <motion.div
            key="results"
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -50 }}
            className="space-y-6"
          >
            
            {/* Threat Score */}
            <div className="glass-morphism-red rounded-2xl p-6 cyber-border-red">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-2xl font-bold text-cyber-red-500 text-glow-red">
                  🚨 Threat Assessment
                </h3>
                <div className="text-right">
                  <div className="text-4xl font-bold text-neon-crimson animate-danger-blink">
                    {analysis.threatScore}/100
                  </div>
                  <div className="text-sm text-gray-400">Threat Score</div>
                </div>
              </div>
              
              {/* Progress Bar */}
              <div className="w-full bg-cyber-darker rounded-full h-4 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${analysis.threatScore}%` }}
                  transition={{ duration: 2, ease: 'easeOut' }}
                  className="h-full bg-gradient-to-r from-cyber-red-500 via-neon-crimson to-alert-danger shadow-neon-red"
                />
              </div>
            </div>

            {/* Security Headers */}
            <div className="glass-morphism-red rounded-2xl p-6 cyber-border-red">
              <h3 className="text-xl font-bold text-cyber-red-500 mb-4 text-glow-red">
                🛡️ Security Validation
              </h3>
              <div className="grid grid-cols-3 gap-4">
                {[
                  { name: 'SPF', status: analysis.spfStatus },
                  { name: 'DKIM', status: analysis.dkimStatus },
                  { name: 'DMARC', status: analysis.dmarcStatus }
                ].map((check) => (
                  <div key={check.name} className="text-center p-4 bg-cyber-blood/20 rounded-lg">
                    <div className={`text-2xl mb-2 ${
                      check.status === 'PASS' ? 'text-green-500' :
                      check.status === 'FAIL' ? 'text-cyber-red-500 animate-danger-blink' :
                      'text-yellow-500 animate-cyber-flicker'
                    }`}>
                      {check.status === 'PASS' ? '✅' : check.status === 'FAIL' ? '❌' : '⚠️'}
                    </div>
                    <div className="font-bold text-gray-300">{check.name}</div>
                    <div className="text-sm text-gray-500">{check.status}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Suspicious Indicators */}
            <div className="glass-morphism-red rounded-2xl p-6 cyber-border-red">
              <h3 className="text-xl font-bold text-cyber-red-500 mb-4 text-glow-red">
                🔍 Threat Indicators
              </h3>
              <div className="space-y-3">
                {analysis.suspiciousIndicators.map((indicator, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center space-x-3 p-3 bg-cyber-blood/20 rounded-lg border border-cyber-red-500/20"
                  >
                    <div className="w-2 h-2 bg-cyber-red-500 rounded-full animate-pulse-red"></div>
                    <span className="text-gray-300">{indicator}</span>
                  </motion.div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}