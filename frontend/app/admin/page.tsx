'use client';

import { useState, useEffect } from 'react';
import { Shield, Activity, Users, AlertTriangle, TrendingUp, Database, Settings, Download, RefreshCw, Eye, Target, Brain, Globe, Lock, Zap, Server, FileX, Mail, Link, Bug, User, KeyRound, X } from 'lucide-react';

function AdminLogin({ onLogin }: { onLogin: (success: boolean) => void }) {
  const [credentials, setCredentials] = useState({ name: '', password: '' });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    // Check credentials
    if (credentials.name === 'Mubashar' && credentials.password === 'Mubashar9266') {
      setTimeout(() => {
        localStorage.setItem('phishnet_admin_authenticated', 'true');
        localStorage.setItem('phishnet_admin_user', JSON.stringify({
          name: 'Mubashar',
          role: 'Super Administrator',
          loginTime: new Date().toISOString()
        }));
        onLogin(true);
        setIsLoading(false);
      }, 1500);
    } else {
      setTimeout(() => {
        setError('Sorry, you are not allowed to see admin rights. Access denied.');
        setIsLoading(false);
      }, 1500);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-dark via-red-900/20 to-cyber-dark flex items-center justify-center relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 cyber-grid opacity-5" />
      <div className="absolute inset-0">
        {[...Array(50)].map((_, i) => (
          <div
            key={i}
            className="absolute w-1 h-1 bg-red-500/30 rounded-full animate-pulse"
            style={{
              top: `${Math.random() * 100}%`,
              left: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 3}s`,
              animationDuration: `${2 + Math.random() * 3}s`
            }}
          />
        ))}
      </div>

      <div className="relative z-10 w-full max-w-md">
        <div className="bg-gradient-to-br from-red-900/30 via-cyber-dark/80 to-red-800/20 backdrop-blur-xl border border-red-500/30 rounded-2xl p-8 shadow-2xl">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-red-500 to-red-700 rounded-full mb-4 shadow-lg">
              <Shield className="h-10 w-10 text-white" />
            </div>
            <h1 className="text-3xl font-bold text-white mb-2">ADMIN ACCESS</h1>
            <p className="text-red-400">Restricted Area - Authorized Personnel Only</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Administrator Name
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  value={credentials.name}
                  onChange={(e) => setCredentials(prev => ({ ...prev, name: e.target.value }))}
                  className="w-full pl-10 pr-4 py-3 bg-cyber-dark/50 border border-red-500/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20"
                  placeholder="Enter admin name"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="password"
                  value={credentials.password}
                  onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                  className="w-full pl-10 pr-4 py-3 bg-cyber-dark/50 border border-red-500/30 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-red-400 focus:ring-2 focus:ring-red-400/20"
                  placeholder="Enter password"
                  required
                />
              </div>
            </div>

            {error && (
              <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-4 flex items-center space-x-3">
                <X className="h-5 w-5 text-red-400 flex-shrink-0" />
                <p className="text-red-400 text-sm">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 disabled:from-gray-600 disabled:to-gray-700 text-white font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 shadow-lg"
            >
              {isLoading ? (
                <div className="flex items-center justify-center space-x-2">
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Verifying Access...</span>
                </div>
              ) : (
                'ACCESS ADMIN PANEL'
              )}
            </button>
          </form>

          <div className="mt-6 text-center">
            <a href="/" className="text-gray-400 hover:text-white text-sm transition-colors">
              ← Back to Main Dashboard
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AdminDashboard() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [stats, setStats] = useState<any>(null);
  const [threats, setThreats] = useState<any[]>([]);
  const [threatDatabase, setThreatDatabase] = useState<any[]>([]);
  const [userActivity, setUserActivity] = useState<any[]>([]);
  const [registeredUsers, setRegisteredUsers] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    // Check if user is authenticated for admin panel
    const adminAuth = localStorage.getItem('phishnet_admin_authenticated');
    const adminUser = localStorage.getItem('phishnet_admin_user');
    
    if (adminAuth === 'true' && adminUser) {
      try {
        const user = JSON.parse(adminUser);
        const loginTime = new Date(user.loginTime);
        const currentTime = new Date();
        const hoursSinceLogin = (currentTime.getTime() - loginTime.getTime()) / (1000 * 60 * 60);
        
        // Session expires after 8 hours
        if (hoursSinceLogin > 8) {
          handleLogout();
          return;
        }
        
        setIsAuthenticated(true);
        fetchDashboardData();
        loadThreatDatabase();
        loadUserActivity();
        loadRegisteredUsers();
        const interval = setInterval(() => {
          fetchDashboardData();
          loadUserActivity();
        }, 30000);
        return () => clearInterval(interval);
      } catch (error) {
        console.error('Error checking admin session:', error);
        handleLogout();
        return;
      }
    }
    setIsCheckingAuth(false);
  }, [isAuthenticated]);

  const handleLogin = (success: boolean) => {
    if (success) {
      setIsAuthenticated(true);
      setIsCheckingAuth(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('phishnet_admin_authenticated');
    localStorage.removeItem('phishnet_admin_user');
    setIsAuthenticated(false);
    window.location.href = '/';
  };

  // Show loading screen while checking authentication
  if (isCheckingAuth) {
    return (
      <div className="min-h-screen bg-cyber-dark flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-cyber-green-500/30 border-t-cyber-green-500 rounded-full animate-spin mb-4 mx-auto" />
          <p className="text-cyber-green-500">Checking admin credentials...</p>
        </div>
      </div>
    );
  }

  // Show login form if not authenticated
  if (!isAuthenticated) {
    return <AdminLogin onLogin={handleLogin} />;
  }

  const fetchDashboardData = async () => {
    try {
      const statsResponse = await fetch('http://127.0.0.1:8005/analytics/dashboard');
      const statsData = await statsResponse.json();
      setStats(statsData);

      const threatResponse = await fetch('http://127.0.0.1:8005/threat-intel/live');
      const threatData = await threatResponse.json();
      setThreats(threatData.recent_threats || []);
      
      setIsLoading(false);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      loadMockData();
      setIsLoading(false);
    }
  };

  const loadMockData = () => {
    setStats({
      metrics: {
        threats_detected_today: 247,
        critical_alerts: 5,
        blocked_emails: 1429,
        accuracy_rate: 97.3
      }
    });
    
    setThreats([
      {
        id: 'TH-2025-001',
        type: 'Phishing',
        severity: 'Critical',
        source: 'fake-bank@secure-login.com',
        timestamp: new Date().toISOString(),
        status: 'Blocked'
      }
    ]);
  };

  const loadThreatDatabase = () => {
    const mockThreatData = [
      {
        id: 'APT-29-2025',
        name: 'Cozy Bear Banking Trojan',
        type: 'Advanced Persistent Threat',
        severity: 'Critical',
        firstSeen: '2025-01-15',
        lastSeen: '2025-10-10',
        affectedCountries: ['USA', 'UK', 'Canada', 'Germany'],
        indicators: {
          domains: ['secure-bank-verify.com', 'banking-alert-center.net'],
          ips: ['192.168.45.67', '10.0.0.1'],
          fileHashes: ['a1b2c3d4e5f6...', '9z8y7x6w5v...']
        },
        description: 'Sophisticated banking trojan targeting financial institutions with AI-powered social engineering.',
        tactics: ['Spear Phishing', 'Credential Harvesting', 'Man-in-the-Middle'],
        mitigation: 'Block all associated domains, quarantine affected systems, implement MFA',
        confidence: 95
      },
      {
        id: 'STORM-2025-PHI',
        name: 'Storm Phishing Campaign',
        type: 'Phishing Campaign',
        severity: 'High',
        firstSeen: '2025-09-20',
        lastSeen: '2025-10-11',
        affectedCountries: ['Global'],
        indicators: {
          domains: ['microsoft-security-alert.org', 'office365-verification.net'],
          ips: ['203.45.67.89', '198.51.100.42'],
          fileHashes: ['f9e8d7c6b5a4...', '3n2m1l0k9j...']
        },
        description: 'Large-scale phishing campaign mimicking Microsoft Office 365 login pages.',
        tactics: ['Email Spoofing', 'Domain Squatting', 'Credential Theft'],
        mitigation: 'Email filtering rules, user awareness training, domain blacklisting',
        confidence: 89
      },
      {
        id: 'RANSOMWARE-X5',
        name: 'BlackCat Ransomware Variant',
        type: 'Ransomware',
        severity: 'Critical',
        firstSeen: '2025-08-30',
        lastSeen: '2025-10-08',
        affectedCountries: ['USA', 'EU', 'Australia'],
        indicators: {
          domains: ['payment-recovery-center.onion'],
          ips: ['172.16.254.1', '10.0.0.2'],
          fileHashes: ['7k6j5h4g3f2d...', 'q9w8e7r6t5y4...']
        },
        description: 'Next-generation ransomware with AI-powered encryption and lateral movement.',
        tactics: ['Double Extortion', 'Living Off The Land', 'API Abuse'],
        mitigation: 'Offline backups, network segmentation, endpoint protection',
        confidence: 98
      }
    ];
    
    setThreatDatabase(mockThreatData);
  };

  const loadUserActivity = () => {
    // Load all user activity from localStorage
    const allActivity: any[] = [];
    
    // Get registered users and their activities
    const savedUsers = JSON.parse(localStorage.getItem('phishnet_registered_users') || '[]');
    
    savedUsers.forEach((user: any) => {
      const userActivityKey = `phishnet_user_activity_${user.id || user.username}`;
      const userActivity = JSON.parse(localStorage.getItem(userActivityKey) || '[]');
      
      userActivity.forEach((activity: any) => {
        allActivity.push({
          ...activity,
          username: user.name || user.username,
          userId: user.id || user.username
        });
      });
    });

    // Also check general activity
    const generalActivity = JSON.parse(localStorage.getItem('phishnet_user_activity') || '[]');
    allActivity.push(...generalActivity);

    // Sort by timestamp (newest first)
    allActivity.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    
    setUserActivity(allActivity.slice(0, 50)); // Show last 50 activities
  };

  const loadRegisteredUsers = () => {
    const savedUsers = JSON.parse(localStorage.getItem('phishnet_registered_users') || '[]');
    
    // Only add demo users if explicitly requested (for now, just use real data)
    // Show actual registered users, or empty list if none
    setRegisteredUsers(savedUsers);
    
    // If no users exist, you can create test data using the debug tool
    if (savedUsers.length === 0) {
      console.log('No registered users found. Use the Debug Tool to create test users.');
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 animate-spin text-blue-500 mx-auto mb-4" />
          <p className="text-xl">Loading Admin Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      {/* Header */}
      <div className="bg-gray-800/50 backdrop-blur-sm border-b border-gray-700 sticky top-0 z-10">
        <div className="container mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-4">
              <Shield className="w-8 h-8 text-red-500" />
              <div>
                <h1 className="text-2xl font-bold text-red-500">PHISHNET ADMIN</h1>
                <p className="text-gray-400 text-sm">Security Operations Center</p>
              </div>
            </div>
            <div className="flex items-center gap-6">
              <div className="flex items-center gap-2 bg-green-600/20 px-3 py-1 rounded-full">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-green-400 text-sm font-medium">System Online</span>
              </div>
              
              {/* Admin User Info */}
              <div className="flex items-center gap-3 bg-red-600/20 px-4 py-2 rounded-lg border border-red-500/30">
                <div className="w-8 h-8 bg-gradient-to-br from-red-500 to-red-700 rounded-full flex items-center justify-center">
                  <User className="h-4 w-4 text-white" />
                </div>
                <div className="text-sm">
                  <div className="text-white font-medium">Mubashar</div>
                  <div className="text-red-400 text-xs">Super Administrator</div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={fetchDashboardData}
                  className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
                  title="Refresh Data"
                >
                  <RefreshCw className="w-5 h-5" />
                </button>

                <a
                  href="http://localhost:8080/test_localstorage.html"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 px-3 py-2 bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/50 rounded-lg transition-all duration-300 hover:scale-105"
                  title="Debug LocalStorage Data"
                >
                  <Database className="h-4 w-4 text-blue-400" />
                  <span className="text-blue-400 text-sm font-medium">Debug Tool</span>
                </a>
                
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-2 px-3 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/50 rounded-lg transition-all duration-300 hover:scale-105"
                  title="Logout"
                >
                  <Lock className="h-4 w-4 text-red-400" />
                  <span className="text-red-400 text-sm font-medium">Logout</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 py-8">
        {/* Navigation Tabs */}
        <div className="flex space-x-1 mb-8 bg-gray-800/40 p-2 rounded-xl">
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'overview'
                ? 'bg-red-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            <Activity className="w-5 h-5 inline mr-2" />
            Overview
          </button>
          <button
            onClick={() => setActiveTab('threats')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'threats'
                ? 'bg-red-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            <Database className="w-5 h-5 inline mr-2" />
            Threat Database
          </button>
          <button
            onClick={() => setActiveTab('intel')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'intel'
                ? 'bg-red-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            <Globe className="w-5 h-5 inline mr-2" />
            Threat Intel
          </button>
          <button
            onClick={() => setActiveTab('users')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'users'
                ? 'bg-purple-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            <Users className="w-5 h-5 inline mr-2" />
            Users & Activity
          </button>
          <button
            onClick={() => setActiveTab('debug')}
            className={`px-6 py-3 rounded-lg font-medium transition-all ${
              activeTab === 'debug'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'text-gray-400 hover:text-white hover:bg-gray-700/50'
            }`}
          >
            <Database className="w-5 h-5 inline mr-2" />
            Debug Tools
          </button>
        </div>

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <>
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Threats Detected Today</p>
                    <p className="text-3xl font-bold text-red-500">{stats?.metrics?.threats_detected_today || 247}</p>
                  </div>
                  <AlertTriangle className="w-8 h-8 text-red-500" />
                </div>
              </div>

              <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Critical Alerts</p>
                    <p className="text-3xl font-bold text-orange-500">{stats?.metrics?.critical_alerts || 5}</p>
                  </div>
                  <Target className="w-8 h-8 text-orange-500" />
                </div>
              </div>

              <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">Emails Blocked</p>
                    <p className="text-3xl font-bold text-green-500">{stats?.metrics?.blocked_emails || 1429}</p>
                  </div>
                  <Mail className="w-8 h-8 text-green-500" />
                </div>
              </div>

              <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-400 text-sm">AI Accuracy</p>
                    <p className="text-3xl font-bold text-blue-500">{stats?.metrics?.accuracy_rate || 97.3}%</p>
                  </div>
                  <Brain className="w-8 h-8 text-blue-500" />
                </div>
              </div>
            </div>

            {/* Recent Threats */}
            <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
              <h2 className="text-xl font-bold text-white mb-6 flex items-center">
                <AlertTriangle className="w-6 h-6 mr-3 text-red-500" />
                Recent Threat Activity
              </h2>
              <div className="space-y-4">
                {threats.length > 0 ? (
                  threats.map((threat, index) => (
                    <div key={threat.id || index} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg border-l-4 border-red-500">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-1">
                          <span className="px-2 py-1 rounded text-xs font-bold bg-red-600">{threat.severity?.toUpperCase()}</span>
                          <span className="text-white font-medium">{threat.type}</span>
                        </div>
                        <p className="text-gray-300 text-sm">{threat.source}</p>
                        <p className="text-gray-500 text-xs mt-1">{new Date(threat.timestamp).toLocaleString()}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-gray-400 text-sm">Status: {threat.status}</p>
                        <p className="text-gray-500 text-xs">ID: {threat.id}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <>
                    <div className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg border-l-4 border-red-500">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-1">
                          <span className="px-2 py-1 rounded text-xs font-bold bg-red-600">CRITICAL</span>
                          <span className="text-white font-medium">Phishing Email Detected</span>
                        </div>
                        <p className="text-gray-300 text-sm">Suspicious email from account-security@example.invalid attempting credential theft</p>
                        <p className="text-gray-500 text-xs mt-1">2 minutes ago</p>
                      </div>
                      <div className="text-right">
                        <p className="text-gray-400 text-sm">Source: Email Gateway</p>
                        <p className="text-gray-500 text-xs">Score: 0.94</p>
                      </div>
                    </div>

                    <div className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg border-l-4 border-orange-500">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-1">
                          <span className="px-2 py-1 rounded text-xs font-bold bg-orange-600">HIGH</span>
                          <span className="text-white font-medium">Malicious URL Blocked</span>
                        </div>
                        <p className="text-gray-300 text-sm">Suspicious domain fake-bank.invalid attempting to mimic legitimate banking site</p>
                        <p className="text-gray-500 text-xs mt-1">5 minutes ago</p>
                      </div>
                      <div className="text-right">
                        <p className="text-gray-400 text-sm">Source: URL Filter</p>
                        <p className="text-gray-500 text-xs">Score: 0.87</p>
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          </>
        )}

        {/* Threat Database Tab */}
        {activeTab === 'threats' && (
          <div className="space-y-6">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">🗂️ Global Threat Intelligence Database</h2>
              <div className="flex items-center gap-4">
                <span className="text-green-400 text-sm">🔄 Auto-updated • Last sync: 2 min ago</span>
                <button className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg transition-colors">
                  <Download className="w-4 h-4 inline mr-2" />
                  Export Report
                </button>
              </div>
            </div>

            <div className="grid gap-6">
              {threatDatabase.map((threat, index) => (
                <div key={threat.id} className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700 hover:border-red-500/50 transition-all">
                  <div className="flex justify-between items-start mb-4">
                    <div className="flex items-center gap-4">
                      <div className={`w-4 h-4 rounded-full ${
                        threat.severity === 'Critical' ? 'bg-red-500' : 
                        threat.severity === 'High' ? 'bg-orange-500' : 'bg-yellow-500'
                      } animate-pulse`}></div>
                      <div>
                        <h3 className="text-xl font-bold text-white">{threat.name}</h3>
                        <p className="text-gray-400">{threat.id} • {threat.type}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                        threat.severity === 'Critical' ? 'bg-red-600 text-white' : 
                        threat.severity === 'High' ? 'bg-orange-600 text-white' : 'bg-yellow-600 text-black'
                      }`}>
                        {threat.severity.toUpperCase()}
                      </span>
                      <p className="text-gray-400 text-sm mt-1">Confidence: {threat.confidence}%</p>
                    </div>
                  </div>

                  <p className="text-gray-300 mb-4">{threat.description}</p>

                  <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
                    <div className="bg-gray-700/50 p-3 rounded-lg">
                      <h4 className="text-red-400 font-semibold mb-2 flex items-center">
                        <Globe className="w-4 h-4 mr-2" />
                        Affected Regions
                      </h4>
                      <div className="flex flex-wrap gap-1">
                        {threat.affectedCountries.map((country: string) => (
                          <span key={country} className="bg-gray-600 px-2 py-1 rounded text-xs">{country}</span>
                        ))}
                      </div>
                    </div>

                    <div className="bg-gray-700/50 p-3 rounded-lg">
                      <h4 className="text-orange-400 font-semibold mb-2 flex items-center">
                        <Target className="w-4 h-4 mr-2" />
                        Tactics & Techniques
                      </h4>
                      <div className="flex flex-wrap gap-1">
                        {threat.tactics.map((tactic: string) => (
                          <span key={tactic} className="bg-orange-600/20 text-orange-300 px-2 py-1 rounded text-xs">{tactic}</span>
                        ))}
                      </div>
                    </div>

                    <div className="bg-gray-700/50 p-3 rounded-lg">
                      <h4 className="text-blue-400 font-semibold mb-2 flex items-center">
                        <Activity className="w-4 h-4 mr-2" />
                        Timeline
                      </h4>
                      <p className="text-gray-300 text-xs">First: {threat.firstSeen}</p>
                      <p className="text-gray-300 text-xs">Latest: {threat.lastSeen}</p>
                    </div>
                  </div>

                  <div className="bg-gray-700/30 p-4 rounded-lg mb-4">
                    <h4 className="text-yellow-400 font-semibold mb-2 flex items-center">
                      <Database className="w-4 h-4 mr-2" />
                      Indicators of Compromise (IoCs)
                    </h4>
                    <div className="grid md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <p className="text-gray-400 font-medium">Domains:</p>
                        {threat.indicators.domains.map((domain: string) => (
                          <p key={domain} className="text-red-300 font-mono text-xs">{domain}</p>
                        ))}
                      </div>
                      <div>
                        <p className="text-gray-400 font-medium">IP Addresses:</p>
                        {threat.indicators.ips.map((ip: string) => (
                          <p key={ip} className="text-orange-300 font-mono text-xs">{ip}</p>
                        ))}
                      </div>
                      <div>
                        <p className="text-gray-400 font-medium">File Hashes:</p>
                        {threat.indicators.fileHashes.map((hash: string) => (
                          <p key={hash} className="text-blue-300 font-mono text-xs">{hash}</p>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="bg-green-900/30 border border-green-700/50 p-3 rounded-lg">
                    <h4 className="text-green-400 font-semibold mb-2 flex items-center">
                      <Shield className="w-4 h-4 mr-2" />
                      Recommended Mitigation
                    </h4>
                    <p className="text-green-200 text-sm">{threat.mitigation}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Threat Intel Tab */}
        {activeTab === 'intel' && (
          <div className="space-y-6">
            <h2 className="text-2xl font-bold text-white">🌐 Live Threat Intelligence Feed</h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
                <h3 className="text-xl font-bold text-red-400 mb-4 flex items-center">
                  <Zap className="w-5 h-5 mr-2" />
                  Active Campaigns
                </h3>
                <div className="space-y-3">
                  <div className="p-3 bg-red-900/30 border border-red-700/50 rounded-lg">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold">Operation Storm Phish</span>
                      <span className="bg-red-600 text-white px-2 py-1 rounded text-xs">ACTIVE</span>
                    </div>
                    <p className="text-gray-300 text-sm mt-1">Large-scale phishing targeting financial sector</p>
                    <p className="text-gray-500 text-xs">Victims: 15,000+ • Success Rate: 12%</p>
                  </div>
                  
                  <div className="p-3 bg-orange-900/30 border border-orange-700/50 rounded-lg">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold">Ransomware Surge 2025</span>
                      <span className="bg-orange-600 text-white px-2 py-1 rounded text-xs">TRENDING</span>
                    </div>
                    <p className="text-gray-300 text-sm mt-1">AI-powered ransomware variants emerging</p>
                    <p className="text-gray-500 text-xs">Incidents: 890+ • Countries: 45</p>
                  </div>
                </div>
              </div>

              <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
                <h3 className="text-xl font-bold text-blue-400 mb-4 flex items-center">
                  <Server className="w-5 h-5 mr-2" />
                  Threat Actor Groups
                </h3>
                <div className="space-y-3">
                  <div className="p-3 bg-blue-900/30 border border-blue-700/50 rounded-lg">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold">APT29 (Cozy Bear)</span>
                      <span className="bg-blue-600 text-white px-2 py-1 rounded text-xs">ACTIVE</span>
                    </div>
                    <p className="text-gray-300 text-sm mt-1">State-sponsored group targeting critical infrastructure</p>
                    <p className="text-gray-500 text-xs">Origin: Russia • Active since: 2008</p>
                  </div>
                  
                  <div className="p-3 bg-purple-900/30 border border-purple-700/50 rounded-lg">
                    <div className="flex justify-between items-center">
                      <span className="font-semibold">Lazarus Group</span>
                      <span className="bg-purple-600 text-white px-2 py-1 rounded text-xs">MONITORED</span>
                    </div>
                    <p className="text-gray-300 text-sm mt-1">Cybercriminal group focused on financial theft</p>
                    <p className="text-gray-500 text-xs">Origin: North Korea • Stolen: $1.7B+</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-800/60 backdrop-blur-sm p-6 rounded-xl border border-gray-700">
              <h3 className="text-xl font-bold text-yellow-400 mb-4 flex items-center">
                <Brain className="w-5 h-5 mr-2" />
                AI-Powered Threat Analysis
              </h3>
              <div className="grid md:grid-cols-3 gap-4">
                <div className="text-center p-4 bg-gradient-to-br from-red-900/30 to-orange-900/30 rounded-lg">
                  <div className="text-3xl font-bold text-red-400">94.7%</div>
                  <div className="text-gray-300 text-sm">Detection Accuracy</div>
                </div>
                <div className="text-center p-4 bg-gradient-to-br from-blue-900/30 to-purple-900/30 rounded-lg">
                  <div className="text-3xl font-bold text-blue-400">&lt; 0.2s</div>
                  <div className="text-gray-300 text-sm">Average Response Time</div>
                </div>
                <div className="text-center p-4 bg-gradient-to-br from-green-900/30 to-teal-900/30 rounded-lg">
                  <div className="text-3xl font-bold text-green-400">99.8%</div>
                  <div className="text-gray-300 text-sm">Threat Mitigation Rate</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="space-y-6">
            {/* User Statistics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-gradient-to-br from-purple-900/50 to-purple-800/30 p-6 rounded-xl border border-purple-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-purple-200 text-sm">Total Users</p>
                    <p className="text-3xl font-bold text-purple-400">{registeredUsers.length}</p>
                  </div>
                  <Users className="w-12 h-12 text-purple-400 opacity-80" />
                </div>
              </div>
              <div className="bg-gradient-to-br from-blue-900/50 to-blue-800/30 p-6 rounded-xl border border-blue-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-blue-200 text-sm">Active Sessions</p>
                    <p className="text-3xl font-bold text-blue-400">
                      {registeredUsers.filter(u => u.lastActive && 
                        new Date(u.lastActive).getTime() > Date.now() - 24*60*60*1000
                      ).length}
                    </p>
                  </div>
                  <Activity className="w-12 h-12 text-blue-400 opacity-80" />
                </div>
              </div>
              <div className="bg-gradient-to-br from-green-900/50 to-green-800/30 p-6 rounded-xl border border-green-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-green-200 text-sm">Threats Detected</p>
                    <p className="text-3xl font-bold text-green-400">
                      {userActivity.filter(a => a.type === 'threat_detected').length}
                    </p>
                  </div>
                  <Target className="w-12 h-12 text-green-400 opacity-80" />
                </div>
              </div>
              <div className="bg-gradient-to-br from-orange-900/50 to-orange-800/30 p-6 rounded-xl border border-orange-500/30">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-orange-200 text-sm">Total Scans</p>
                    <p className="text-3xl font-bold text-orange-400">
                      {userActivity.filter(a => ['email_scan', 'url_scan', 'file_scan'].includes(a.type)).length}
                    </p>
                  </div>
                  <Eye className="w-12 h-12 text-orange-400 opacity-80" />
                </div>
              </div>
            </div>

            {/* Users Table */}
            <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700 overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-700">
                <h3 className="text-xl font-semibold text-purple-400 flex items-center">
                  <Users className="w-6 h-6 mr-2" />
                  Registered Users
                </h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-700/50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">User</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Role</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Registered</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Activity</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {registeredUsers.map((user, index) => {
                      const userScans = userActivity.filter(a => a.userId === user.id);
                      const lastActive = user.lastActive ? new Date(user.lastActive) : null;
                      const isActive = lastActive && (Date.now() - lastActive.getTime() < 24*60*60*1000);
                      
                      return (
                        <tr key={index} className="hover:bg-gray-700/30">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <div className="w-10 h-10 bg-gradient-to-br from-purple-500 to-purple-600 rounded-full flex items-center justify-center">
                                <span className="text-white font-bold">{(user.name || user.username)[0].toUpperCase()}</span>
                              </div>
                              <div className="ml-4">
                                <div className="text-sm font-medium text-white">{user.name || user.username}</div>
                                <div className="text-sm text-gray-400">{user.email}</div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                              user.role === 'Administrator' ? 'bg-red-900/50 text-red-300' :
                              user.role === 'Analyst' ? 'bg-blue-900/50 text-blue-300' :
                              'bg-green-900/50 text-green-300'
                            }`}>
                              {user.role || 'User'}
                            </span>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                            {user.registeredAt ? new Date(user.registeredAt).toLocaleDateString() : 'Unknown'}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                            {userScans.length} scans
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                              isActive ? 'bg-green-900/50 text-green-300' : 'bg-gray-700/50 text-gray-400'
                            }`}>
                              {isActive ? 'Active' : 'Offline'}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700">
              <div className="px-6 py-4 border-b border-gray-700">
                <h3 className="text-xl font-semibold text-blue-400 flex items-center">
                  <Activity className="w-6 h-6 mr-2" />
                  Recent User Activity
                </h3>
              </div>
              <div className="p-6">
                <div className="space-y-4 max-h-96 overflow-y-auto">
                  {userActivity.slice(0, 20).map((activity, index) => (
                    <div key={index} className="flex items-center space-x-4 p-3 bg-gray-700/30 rounded-lg">
                      <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
                        activity.type === 'threat_detected' ? 'bg-red-600' :
                        activity.type === 'email_scan' ? 'bg-blue-600' :
                        activity.type === 'url_scan' ? 'bg-green-600' :
                        activity.type === 'file_scan' ? 'bg-purple-600' :
                        'bg-gray-600'
                      }`}>
                        {activity.type === 'threat_detected' ? <AlertTriangle className="w-5 h-5" /> :
                         activity.type === 'email_scan' ? <Mail className="w-5 h-5" /> :
                         activity.type === 'url_scan' ? <Link className="w-5 h-5" /> :
                         activity.type === 'file_scan' ? <FileX className="w-5 h-5" /> :
                         <Activity className="w-5 h-5" />}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="text-white font-medium">{activity.username || 'Unknown User'}</span>
                          <span className="text-gray-400 text-sm">
                            {activity.timestamp ? new Date(activity.timestamp).toLocaleString() : 'No timestamp'}
                          </span>
                        </div>
                        <p className="text-gray-300 text-sm">
                          {activity.type === 'threat_detected' ? `🚨 Threat detected: ${activity.result || 'Unknown threat'}` :
                           activity.type === 'email_scan' ? `📧 Email scan: ${activity.result || 'Scanned email'}` :
                           activity.type === 'url_scan' ? `🔗 URL scan: ${activity.target || 'URL scanned'}` :
                           activity.type === 'file_scan' ? `📁 File scan: ${activity.target || 'File scanned'}` :
                           activity.description || 'User activity'}
                        </p>
                      </div>
                    </div>
                  ))}
                  {userActivity.length === 0 && (
                    <div className="text-center py-8 text-gray-400">
                      <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>No user activity recorded yet</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Debug Tab */}
        {activeTab === 'debug' && (
          <div className="space-y-6">
            <div className="bg-gray-800/50 backdrop-blur-sm rounded-xl border border-gray-700 p-6">
              <h3 className="text-xl font-bold text-blue-400 mb-6 flex items-center">
                <Database className="w-6 h-6 mr-3" />
                Debug & Development Tools
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* LocalStorage Debug Tool */}
                <div className="bg-gray-700/30 rounded-lg p-4 border border-blue-500/30">
                  <h4 className="text-lg font-semibold text-blue-300 mb-3 flex items-center">
                    <Database className="w-5 h-5 mr-2" />
                    LocalStorage Debug Tool
                  </h4>
                  <p className="text-gray-400 mb-4 text-sm">
                    Inspect and debug localStorage data including user registration, activity logs, and admin settings.
                  </p>
                  <a
                    href="http://localhost:8080/test_localstorage.html"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                  >
                    <Database className="w-4 h-4 mr-2" />
                    Open Debug Tool
                  </a>
                </div>

                {/* Data Statistics */}
                <div className="bg-gray-700/30 rounded-lg p-4 border border-green-500/30">
                  <h4 className="text-lg font-semibold text-green-300 mb-3 flex items-center">
                    <TrendingUp className="w-5 h-5 mr-2" />
                    Data Statistics
                  </h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Registered Users:</span>
                      <span className="text-white font-medium">{registeredUsers.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Activity Records:</span>
                      <span className="text-white font-medium">{userActivity.length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Current User:</span>
                      <span className="text-white font-medium">
                        {typeof window !== 'undefined' && localStorage.getItem('phishnet_user') ? 'Logged In' : 'None'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Quick Actions */}
                <div className="bg-gray-700/30 rounded-lg p-4 border border-yellow-500/30">
                  <h4 className="text-lg font-semibold text-yellow-300 mb-3 flex items-center">
                    <Settings className="w-5 h-5 mr-2" />
                    Quick Actions
                  </h4>
                  <div className="space-y-2">
                    <button
                      onClick={() => {
                        loadUserActivity();
                        loadRegisteredUsers();
                      }}
                      className="w-full text-left px-3 py-2 bg-gray-600/50 hover:bg-gray-600 rounded text-sm transition-colors"
                    >
                      🔄 Refresh All Data
                    </button>
                    <button
                      onClick={() => {
                        if (confirm('This will clear all PHISHNET localStorage data. Continue?')) {
                          Object.keys(localStorage).forEach(key => {
                            if (key.startsWith('phishnet_')) {
                              localStorage.removeItem(key);
                            }
                          });
                          alert('All PHISHNET data cleared!');
                          window.location.reload();
                        }
                      }}
                      className="w-full text-left px-3 py-2 bg-red-600/50 hover:bg-red-600 rounded text-sm transition-colors text-red-300"
                    >
                      🗑️ Clear All LocalStorage Data
                    </button>
                  </div>
                </div>

                {/* System Information */}
                <div className="bg-gray-700/30 rounded-lg p-4 border border-purple-500/30">
                  <h4 className="text-lg font-semibold text-purple-300 mb-3 flex items-center">
                    <Server className="w-5 h-5 mr-2" />
                    System Information
                  </h4>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Frontend:</span>
                      <span className="text-green-400 font-medium">http://localhost:3001</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Backend:</span>
                      <span className="text-green-400 font-medium">http://localhost:8005</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Debug Server:</span>
                      <span className="text-green-400 font-medium">http://localhost:8080</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Admin Access:</span>
                      <span className="text-green-400 font-medium">Mubashar</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}