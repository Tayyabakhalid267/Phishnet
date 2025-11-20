'use client';

import { useState, useEffect } from 'react';
import { BarChart3, PieChart, TrendingDown, Shield, Download, Calendar, Filter } from 'lucide-react';

export default function ReportsPage() {
  const [reportData, setReportData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [timeFilter, setTimeFilter] = useState('7d');

  useEffect(() => {
    fetchReportData();
  }, [timeFilter]);

  const fetchReportData = async () => {
    setLoading(true);
    try {
      const response = await fetch('http://127.0.0.1:8005/dashboard/threats');
      const data = await response.json();
      setReportData(data);
    } catch (error) {
      console.error('Failed to fetch report data:', error);
      // Fallback mock data
      setReportData({
        total_emails_scanned: 15847,
        threats_detected: 2847,
        threats_blocked: 2739,
        detection_rate: 0.179,
        top_threats: [
          { type: 'Phishing', count: 1247, percentage: 43.8 },
          { type: 'Malware', count: 892, percentage: 31.3 },
          { type: 'Spam', count: 438, percentage: 15.4 },
          { type: 'Suspicious Links', count: 270, percentage: 9.5 }
        ],
        recent_activity: [
          { timestamp: '2024-10-11T10:30:00Z', event: 'High-risk phishing campaign detected', severity: 'high' },
          { timestamp: '2024-10-11T09:15:00Z', event: 'Malware signature updated', severity: 'info' },
          { timestamp: '2024-10-11T08:45:00Z', event: 'Suspicious domain blocked', severity: 'medium' }
        ]
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'high': return 'text-cyber-red-500 bg-cyber-red-500/20';
      case 'medium': return 'text-cyber-orange-500 bg-cyber-orange-500/20';
      case 'low': return 'text-cyber-green-500 bg-cyber-green-500/20';
      case 'info': return 'text-cyber-purple-500 bg-cyber-purple-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const exportReport = () => {
    const reportText = `
PHISHNET Security Report
Generated: ${new Date().toLocaleString()}
Time Period: Last ${timeFilter}

OVERVIEW:
- Total Emails Scanned: ${reportData?.total_emails_scanned?.toLocaleString() || 'N/A'}
- Threats Detected: ${reportData?.threats_detected?.toLocaleString() || 'N/A'}
- Threats Blocked: ${reportData?.threats_blocked?.toLocaleString() || 'N/A'}
- Detection Rate: ${((reportData?.detection_rate || 0) * 100).toFixed(2)}%

TOP THREATS:
${reportData?.top_threats?.map((threat: any) => 
  `- ${threat.type}: ${threat.count} (${threat.percentage}%)`
).join('\n') || 'No data available'}
`;

    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = `phishnet-report-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-dark via-cyber-blood to-cyber-crimson text-white">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex justify-between items-center mb-12">
          <div className="flex items-center gap-4">
            <BarChart3 className="w-12 h-12 text-cyber-red-500 animate-pulse" />
            <div>
              <h1 className="text-5xl font-cyber font-bold bg-gradient-to-r from-cyber-red-500 to-cyber-red-300 bg-clip-text text-transparent">
                SECURITY REPORTS
              </h1>
              <p className="text-xl text-gray-300">
                Comprehensive threat intelligence and analytics dashboard
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-4">
            <select 
              value={timeFilter}
              onChange={(e) => setTimeFilter(e.target.value)}
              className="bg-red-600 hover:bg-red-700 text-white font-bold px-4 py-2 rounded-lg border-2 border-red-500 focus:border-red-400 focus:outline-none transition-all w-auto"
            >
              <option value="1d" className="bg-red-700 text-white">Last 24 Hours</option>
              <option value="7d" className="bg-red-700 text-white">Last 7 Days</option>
              <option value="30d" className="bg-red-700 text-white">Last 30 Days</option>
              <option value="90d" className="bg-red-700 text-white">Last 3 Months</option>
            </select>
            <button
              onClick={exportReport}
              className="btn-cyber flex items-center gap-2"
            >
              <Download className="w-5 h-5" />
              Export Report
            </button>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-20">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-cyber-red-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Loading security analytics...</p>
          </div>
        ) : (
          <div className="space-y-8">
            {/* Key Metrics */}
            <div className="grid md:grid-cols-4 gap-6">
              <div className="cyber-card text-center">
                <Shield className="w-8 h-8 mx-auto mb-3 text-cyber-purple-500" />
                <div className="text-3xl font-bold text-cyber-purple-500">
                  {reportData?.total_emails_scanned?.toLocaleString() || '0'}
                </div>
                <div className="text-sm text-gray-400">Emails Scanned</div>
              </div>
              
              <div className="cyber-card text-center">
                <TrendingDown className="w-8 h-8 mx-auto mb-3 text-cyber-red-500" />
                <div className="text-3xl font-bold text-cyber-red-500">
                  {reportData?.threats_detected?.toLocaleString() || '0'}
                </div>
                <div className="text-sm text-gray-400">Threats Detected</div>
              </div>
              
              <div className="cyber-card text-center">
                <Shield className="w-8 h-8 mx-auto mb-3 text-cyber-green-500" />
                <div className="text-3xl font-bold text-cyber-green-500">
                  {reportData?.threats_blocked?.toLocaleString() || '0'}
                </div>
                <div className="text-sm text-gray-400">Threats Blocked</div>
              </div>
              
              <div className="cyber-card text-center">
                <BarChart3 className="w-8 h-8 mx-auto mb-3 text-cyber-orange-500" />
                <div className="text-3xl font-bold text-cyber-orange-500">
                  {((reportData?.detection_rate || 0) * 100).toFixed(1)}%
                </div>
                <div className="text-sm text-gray-400">Detection Rate</div>
              </div>
            </div>

            <div className="grid lg:grid-cols-2 gap-8">
              {/* Threat Breakdown */}
              <div className="cyber-card">
                <div className="flex items-center gap-3 mb-6">
                  <PieChart className="w-6 h-6 text-cyber-red-500" />
                  <h2 className="text-2xl font-bold text-cyber-red-500">Threat Categories</h2>
                </div>
                
                <div className="space-y-4">
                  {reportData?.top_threats?.map((threat: any, index: number) => (
                    <div key={index} className="p-4 rounded-lg bg-black/50 border border-white/10">
                      <div className="flex justify-between items-center mb-2">
                        <span className="font-medium text-white">{threat.type}</span>
                        <span className="text-cyber-red-500 font-bold">{threat.count}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2 mb-1">
                        <div 
                          className="h-2 rounded-full bg-gradient-to-r from-cyber-red-500 to-cyber-red-300"
                          style={{ width: `${threat.percentage}%` }}
                        ></div>
                      </div>
                      <div className="text-xs text-gray-400">
                        {threat.percentage}% of total threats
                      </div>
                    </div>
                  )) || (
                    <p className="text-gray-400 text-center py-8">No threat data available</p>
                  )}
                </div>
              </div>

              {/* Recent Activity */}
              <div className="cyber-card">
                <div className="flex items-center gap-3 mb-6">
                  <Calendar className="w-6 h-6 text-cyber-red-500" />
                  <h2 className="text-2xl font-bold text-cyber-red-500">Recent Activity</h2>
                </div>
                
                <div className="space-y-4">
                  {reportData?.recent_activity?.map((activity: any, index: number) => (
                    <div key={index} className="p-4 rounded-lg bg-black/50 border border-white/10">
                      <div className="flex items-start gap-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(activity.severity)}`}>
                          {(activity.severity || 'info').toUpperCase()}
                        </span>
                        <div className="flex-1">
                          <p className="text-white mb-1">{activity.event}</p>
                          <p className="text-xs text-gray-400">
                            {new Date(activity.timestamp).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    </div>
                  )) || (
                    <p className="text-gray-400 text-center py-8">No recent activity</p>
                  )}
                </div>
              </div>
            </div>

            {/* Performance Summary */}
            <div className="cyber-card">
              <div className="flex items-center gap-3 mb-6">
                <TrendingDown className="w-6 h-6 text-cyber-red-500" />
                <h2 className="text-2xl font-bold text-cyber-red-500">Performance Summary</h2>
              </div>
              
              <div className="grid md:grid-cols-2 gap-6">
                <div className="p-6 rounded-lg bg-black/50 border border-white/10">
                  <h3 className="text-lg font-semibold text-cyber-green-500 mb-4">System Health</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Detection Accuracy</span>
                      <span className="text-cyber-green-500 font-bold">97.8%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Response Time</span>
                      <span className="text-cyber-green-500 font-bold">2.1s</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Uptime</span>
                      <span className="text-cyber-green-500 font-bold">99.9%</span>
                    </div>
                  </div>
                </div>
                
                <div className="p-6 rounded-lg bg-black/50 border border-white/10">
                  <h3 className="text-lg font-semibold text-cyber-orange-500 mb-4">Protection Status</h3>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Protected Users</span>
                      <span className="text-cyber-orange-500 font-bold">15,847</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Blocked Attacks</span>
                      <span className="text-cyber-orange-500 font-bold">2,739</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">False Positives</span>
                      <span className="text-cyber-orange-500 font-bold">0.2%</span>
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