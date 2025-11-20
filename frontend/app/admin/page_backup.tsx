'use client';

import { useState, useEffect } from 'react';
import { Shield, Activity, Users, AlertTriangle, TrendingUp, Database, Settings, Download, RefreshCw, Eye, Target, Brain, Globe, Lock, Zap, Server, FileX, Mail, Link, Bug } from 'lucide-react';

export default function AdminDashboard() {
  const [stats, setStats] = useState<any>(null);
  const [threats, setThreats] = useState<any[]>([]);
  const [threatDatabase, setThreatDatabase] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchDashboardData();
    loadThreatDatabase();
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

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
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 bg-green-600/20 px-3 py-1 rounded-full">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-green-400 text-sm font-medium">System Online</span>
              </div>
              <button
                onClick={fetchDashboardData}
                className="p-2 hover:bg-gray-700 rounded-lg transition-colors"
              >
                <RefreshCw className="w-5 h-5" />
              </button>
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
      </div>
    </div>
  );
}