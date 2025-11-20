'use client'

export default function Footer() {
  return (
    <footer className="bg-cyber-darker border-t border-white/10">
      <div className="container mx-auto px-4 py-12">
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-2 mb-4">
              <div className="w-8 h-8 rounded bg-cyber-green-500 flex items-center justify-center">
                <span className="text-black font-bold">🧠</span>
              </div>
              <h3 className="text-xl font-bold text-cyber-green-500 font-cyber">
                PHISHNET
              </h3>
            </div>
            <p className="text-gray-400 mb-4 max-w-md">
              Advanced AI-powered cybersecurity suite for detecting, analyzing, and neutralizing 
              phishing threats in real-time. Protect your organization with cutting-edge technology.
            </p>
            <div className="flex space-x-4">
              <a href="#" className="text-gray-400 hover:text-cyber-green-500 transition-colors">
                <span className="sr-only">Twitter</span>
                🐦
              </a>
              <a href="#" className="text-gray-400 hover:text-cyber-green-500 transition-colors">
                <span className="sr-only">GitHub</span>
                🐙
              </a>
              <a href="#" className="text-gray-400 hover:text-cyber-green-500 transition-colors">
                <span className="sr-only">LinkedIn</span>
                💼
              </a>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h4 className="text-lg font-semibold text-white mb-4">Platform</h4>
            <ul className="space-y-2 text-gray-400">
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Dashboard</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Email Scanner</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">URL Analyzer</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Threat Map</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">API Docs</a></li>
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h4 className="text-lg font-semibold text-white mb-4">Resources</h4>
            <ul className="space-y-2 text-gray-400">
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Documentation</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Security Guide</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Best Practices</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Threat Intel</a></li>
              <li><a href="#" className="hover:text-cyber-green-500 transition-colors">Support</a></li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="border-t border-white/10 mt-8 pt-8 flex flex-col md:flex-row justify-between items-center">
          <p className="text-gray-400 text-sm">
            © 2024 PHISHNET. All rights reserved. Built with ❤️ for cybersecurity.
          </p>
          <div className="flex space-x-6 mt-4 md:mt-0">
            <a href="#" className="text-gray-400 hover:text-cyber-green-500 text-sm transition-colors">
              Privacy Policy
            </a>
            <a href="#" className="text-gray-400 hover:text-cyber-green-500 text-sm transition-colors">
              Terms of Service
            </a>
            <a href="#" className="text-gray-400 hover:text-cyber-green-500 text-sm transition-colors">
              Security
            </a>
          </div>
        </div>

        {/* Status Bar */}
        <div className="mt-6 flex flex-wrap justify-center gap-6 text-sm">
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-cyber-green-500 rounded-full animate-pulse"></div>
            <span className="text-cyber-green-500">System Status: Operational</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-cyber-blue-500 rounded-full animate-pulse"></div>
            <span className="text-cyber-blue-500">API: Online</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-cyber-green-500 rounded-full animate-pulse"></div>
            <span className="text-cyber-green-500">Threat Feeds: Active</span>
          </div>
        </div>
      </div>
    </footer>
  )
}