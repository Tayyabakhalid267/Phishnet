'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import Link from 'next/link'

export default function Navbar() {
  const [isOpen, setIsOpen] = useState(false)
  const [isAdminAuthenticated, setIsAdminAuthenticated] = useState(false)

  useEffect(() => {
    // Check admin authentication status
    const adminAuth = localStorage.getItem('phishnet_admin_authenticated')
    setIsAdminAuthenticated(adminAuth === 'true')
  }, [])

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-effect border-b border-white/10">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo */}
          <Link href="/" className="flex items-center space-x-2 group">
            <div className="relative">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyber-green-500 to-cyber-blue-500 flex items-center justify-center group-hover:shadow-neon-green transition-all duration-300">
                <span className="text-black font-bold text-lg">🧠</span>
              </div>
              <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-cyber-green-500 to-cyber-blue-500 opacity-0 group-hover:opacity-20 blur-lg transition-all duration-300"></div>
            </div>
            <div className="hidden sm:block">
              <h1 className="text-xl font-bold text-cyber-green-500 font-cyber group-hover:text-glow transition-all duration-300">
                PHISHNET
              </h1>
              <p className="text-xs text-gray-400 -mt-1">AI Cybersecurity</p>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <NavLink href="/" label="🏠 Dashboard" />
            <NavLink href="/scan" label="🔍 Scan" />
            <NavLink href="/campaigns" label="🎯 Campaigns" />
            <NavLink href="/reports" label="📊 Reports" />
            <NavLink href="/admin" label="⚙️ Admin" />
          </div>

          {/* Status Indicators */}
          <div className="hidden lg:flex items-center space-x-4">
            <div className="flex items-center space-x-2 text-sm">
              <div className="w-2 h-2 bg-cyber-green-500 rounded-full animate-pulse"></div>
              <span className="text-cyber-green-500">AI Active</span>
            </div>
            <div className="flex items-center space-x-2 text-sm">
              <div className="w-2 h-2 bg-cyber-blue-500 rounded-full animate-pulse"></div>
              <span className="text-cyber-blue-500">Feeds Online</span>
            </div>
            {isAdminAuthenticated && (
              <div className="flex items-center space-x-2 text-sm">
                <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                <span className="text-red-400">Admin Mode</span>
              </div>
            )}
          </div>

          {/* User Menu */}
          <div className="flex items-center space-x-4">
            
            {/* Notifications */}
            <button className="relative p-2 rounded-lg hover:bg-white/10 transition-colors">
              <svg className="w-6 h-6 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-5 5v-5z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 7h6a2 2 0 012 2v9a2 2 0 01-2 2H9a2 2 0 01-2-2V9a2 2 0 012-2z" />
              </svg>
              <div className="absolute -top-1 -right-1 w-3 h-3 bg-cyber-red-500 rounded-full"></div>
            </button>

            {/* User Avatar */}
            <div className="flex items-center space-x-2">
              <img 
                src="https://ui-avatars.com/api/?name=Admin&background=00ff88&color=000"
                alt="User Avatar"
                className="w-8 h-8 rounded-full border border-cyber-green-500/30"
              />
              <span className="hidden sm:block text-sm text-gray-300">Admin</span>
            </div>

            {/* Mobile Menu Button */}
            <button 
              onClick={() => setIsOpen(!isOpen)}
              className="md:hidden p-2 rounded-lg hover:bg-white/10 transition-colors"
            >
              <svg className="w-6 h-6 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {isOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden border-t border-white/10 py-4"
          >
            <div className="space-y-2">
              <MobileNavLink href="/" label="🏠 Dashboard" />
              <MobileNavLink href="/scan" label="🔍 Scan" />
              <MobileNavLink href="/campaigns" label="🎯 Campaigns" />
              <MobileNavLink href="/reports" label="📊 Reports" />
              <MobileNavLink href="/admin" label="⚙️ Admin" />
            </div>
            
            {/* Mobile Status */}
            <div className="mt-4 pt-4 border-t border-white/10">
              <div className="flex justify-between text-sm">
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-cyber-green-500 rounded-full animate-pulse"></div>
                  <span className="text-cyber-green-500">AI Active</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-cyber-blue-500 rounded-full animate-pulse"></div>
                  <span className="text-cyber-blue-500">Feeds Online</span>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </nav>
  )
}

function NavLink({ href, label }: { href: string; label: string }) {
  return (
    <Link 
      href={href}
      className="text-gray-300 hover:text-cyber-green-500 transition-colors duration-200 font-medium relative group"
    >
      {label}
      <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-cyber-green-500 transition-all duration-300 group-hover:w-full"></span>
    </Link>
  )
}

function MobileNavLink({ href, label }: { href: string; label: string }) {
  return (
    <Link 
      href={href}
      className="block px-4 py-2 text-gray-300 hover:text-cyber-green-500 hover:bg-white/5 rounded-lg transition-all duration-200"
    >
      {label}
    </Link>
  )
}