'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, User, LogOut, Activity, Target } from 'lucide-react'
import Navbar from '@/components/Navbar'
import Hero from '@/components/Hero'
import ScanInterface from '@/components/ScanInterface'
import LiveStats from '@/components/LiveStats'
import ThreatMap from '@/components/ThreatMap'
import Footer from '@/components/Footer'


function HomePage() {
  const [isLoading, setIsLoading] = useState(true)
  const [scanMode, setScanMode] = useState<'email' | 'url' | 'file' | null>(null)
  const [user, setUser] = useState<any>(null)

  useEffect(() => {
    const savedUser = localStorage.getItem('phishnet_user');
    if (savedUser) {
      setUser(JSON.parse(savedUser));
    }
    const timer = setTimeout(() => setIsLoading(false), 2000)
    return () => clearTimeout(timer)
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('phishnet_user');
    localStorage.removeItem('phishnet_authenticated');
    window.location.href = '/auth';
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-cyber-dark">
        <div className="text-center">
          <h1 className="text-3xl font-bold text-cyber-green-500 font-cyber"> PHISHNET</h1>
          <p className="text-lg text-cyber-blue-500">Loading...</p>
        </div>
      </div>
    )
  }

  const UserWelcomeBar = () => {
    if (!user) return null;
    
    const userActivity = JSON.parse(localStorage.getItem('phishnet_user_activity') || '[]');
    const threatCount = userActivity.filter((activity: any) => activity.type === 'threat_detected').length;
    const scanCount = userActivity.filter((activity: any) => 
      activity.type && ['email_scan', 'url_scan', 'file_scan'].includes(activity.type)
    ).length;
    
    return (
      <div className="fixed top-16 left-0 right-0 z-40 bg-gradient-to-r from-cyber-dark via-cyber-green-900/20 to-cyber-dark border-b border-cyber-green-500/30 backdrop-blur-md">
        <div className="container mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <div className="w-8 h-8 bg-gradient-to-br from-cyber-green-500 to-cyber-blue-500 rounded-full flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                <div>
                  <span className="text-white font-bold text-lg">Welcome, {user.name || user.username}!</span>
                  <div className="text-cyber-green-400 text-xs">SecOps Agent • Active Protection</div>
                </div>
                <div className="flex items-center space-x-1 ml-4">
                  <Shield className="h-4 w-4 text-green-400 animate-pulse" />
                  <span className="text-green-400 text-sm font-medium">SECURED</span>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-4">
                <div className="text-center">
                  <div className="flex items-center space-x-1">
                    <Target className="h-4 w-4 text-red-400" />
                    <span className="text-red-400 font-bold text-lg">{threatCount}</span>
                  </div>
                  <div className="text-gray-400 text-xs">Threats Blocked</div>
                </div>
                <div className="text-center">
                  <div className="flex items-center space-x-1">
                    <Activity className="h-4 w-4 text-cyber-blue-400" />
                    <span className="text-cyber-blue-400 font-bold text-lg">{scanCount}</span>
                  </div>
                  <div className="text-gray-400 text-xs">Scans Today</div>
                </div>
              </div>
              <button onClick={handleLogout} className="flex items-center space-x-1 px-3 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/50 rounded-lg transition-all duration-300 hover:scale-105">
                <LogOut className="h-4 w-4 text-red-400" />
                <span className="text-red-400 text-sm font-medium">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-cyber-dark">
      <Navbar />
      <UserWelcomeBar />
      <div className="pt-32"> {/* Account for both navbar (64px) and welcome bar (~64px) */}
        <Hero onScanModeChange={setScanMode} />
        <div className="container mx-auto px-6 py-8">
          <ScanInterface mode={scanMode} onClose={() => setScanMode(null)} />
        </div>
        <LiveStats />
        <ThreatMap />
        <Footer />
      </div>
    </div>
  )
}

export default function MainPage() {
  return <HomePage />
}
