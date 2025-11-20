'use client';

import { useState, useEffect } from 'react';
import { Target, Users, TrendingUp, AlertCircle, Calendar, Activity } from 'lucide-react';

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const fetchCampaigns = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8005/detect/campaign');
      const data = await response.json();
      setCampaigns(data.active_campaigns || []);
    } catch (error) {
      console.error('Failed to fetch campaigns:', error);
      // Fallback mock data
      setCampaigns([
        {
          id: 'camp_001',
          name: 'Banking Phishing Campaign',
          threat_actor: 'APT-Banking-001',
          targets: 1247,
          success_rate: 0.23,
          status: 'active',
          start_date: '2024-10-01T00:00:00Z'
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'active': return 'text-cyber-red-500 bg-cyber-red-500/20';
      case 'monitoring': return 'text-cyber-orange-500 bg-cyber-orange-500/20';
      case 'resolved': return 'text-cyber-green-500 bg-cyber-green-500/20';
      default: return 'text-gray-400 bg-gray-500/20';
    }
  };

  const getRiskLevel = (successRate: number) => {
    if (successRate > 0.5) return { level: 'High', color: 'text-cyber-red-500' };
    if (successRate > 0.2) return { level: 'Medium', color: 'text-cyber-orange-500' };
    return { level: 'Low', color: 'text-cyber-green-500' };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-cyber-dark via-cyber-blood to-cyber-crimson text-white">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center items-center gap-4 mb-6">
            <Target className="w-12 h-12 text-cyber-red-500 animate-pulse" />
            <h1 className="text-5xl font-cyber font-bold bg-gradient-to-r from-cyber-red-500 to-cyber-red-300 bg-clip-text text-transparent">
              CAMPAIGN TRACKER
            </h1>
            <Activity className="w-12 h-12 text-cyber-red-500 animate-pulse" />
          </div>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto">
            Real-time monitoring and analysis of active phishing campaigns
          </p>
        </div>

        {/* Stats Overview */}
        <div className="grid md:grid-cols-4 gap-6 mb-8">
          <div className="cyber-card text-center">
            <Target className="w-8 h-8 mx-auto mb-3 text-cyber-red-500" />
            <div className="text-2xl font-bold text-cyber-red-500">{campaigns.length}</div>
            <div className="text-sm text-gray-400">Active Campaigns</div>
          </div>
          
          <div className="cyber-card text-center">
            <Users className="w-8 h-8 mx-auto mb-3 text-cyber-orange-500" />
            <div className="text-2xl font-bold text-cyber-orange-500">
              {campaigns.reduce((sum, c) => sum + (c.targets || 0), 0).toLocaleString()}
            </div>
            <div className="text-sm text-gray-400">Total Targets</div>
          </div>
          
          <div className="cyber-card text-center">
            <TrendingUp className="w-8 h-8 mx-auto mb-3 text-cyber-purple-500" />
            <div className="text-2xl font-bold text-cyber-purple-500">
              {campaigns.length > 0 ? 
                (campaigns.reduce((sum, c) => sum + (c.success_rate || 0), 0) / campaigns.length * 100).toFixed(1) + '%' 
                : '0%'
              }
            </div>
            <div className="text-sm text-gray-400">Avg Success Rate</div>
          </div>
          
          <div className="cyber-card text-center">
            <AlertCircle className="w-8 h-8 mx-auto mb-3 text-cyber-green-500" />
            <div className="text-2xl font-bold text-cyber-green-500">
              {campaigns.filter(c => c.status === 'active').length}
            </div>
            <div className="text-sm text-gray-400">High Priority</div>
          </div>
        </div>

        {/* Campaigns List */}
        <div className="cyber-card">
          <div className="flex items-center gap-3 mb-6">
            <Target className="w-6 h-6 text-cyber-red-500" />
            <h2 className="text-2xl font-bold text-cyber-red-500">Active Campaigns</h2>
          </div>

          {loading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-red-500 mx-auto mb-4"></div>
              <p className="text-gray-400">Loading campaign data...</p>
            </div>
          ) : campaigns.length === 0 ? (
            <div className="text-center py-12">
              <Target className="w-16 h-16 mx-auto text-gray-600 mb-4" />
              <p className="text-gray-400">No active campaigns detected</p>
            </div>
          ) : (
            <div className="space-y-4">
              {campaigns.map((campaign, index) => {
                const risk = getRiskLevel(campaign.success_rate || 0);
                return (
                  <div key={campaign.id || index} className="p-6 rounded-lg bg-black/50 border border-white/10 hover:border-cyber-red-500/30 transition-all">
                    <div className="grid md:grid-cols-4 gap-4">
                      <div className="md:col-span-2">
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="text-lg font-semibold text-white">
                            {campaign.name || `Campaign ${index + 1}`}
                          </h3>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(campaign.status)}`}>
                            {(campaign.status || 'unknown').toUpperCase()}
                          </span>
                        </div>
                        <p className="text-gray-400 text-sm mb-2">
                          Threat Actor: {campaign.threat_actor || 'Unknown'}
                        </p>
                        <div className="flex items-center gap-4 text-sm">
                          <div className="flex items-center gap-1">
                            <Calendar className="w-4 h-4 text-gray-400" />
                            <span className="text-gray-400">
                              {campaign.start_date ? new Date(campaign.start_date).toLocaleDateString() : 'Unknown'}
                            </span>
                          </div>
                        </div>
                      </div>
                      
                      <div className="text-center">
                        <div className="text-2xl font-bold text-cyber-orange-500">
                          {(campaign.targets || 0).toLocaleString()}
                        </div>
                        <div className="text-xs text-gray-400">Targets</div>
                      </div>
                      
                      <div className="text-center">
                        <div className={`text-2xl font-bold ${risk.color}`}>
                          {((campaign.success_rate || 0) * 100).toFixed(1)}%
                        </div>
                        <div className="text-xs text-gray-400">Success Rate</div>
                        <div className={`text-xs ${risk.color} mt-1`}>
                          {risk.level} Risk
                        </div>
                      </div>
                    </div>
                    
                    <div className="mt-4 pt-4 border-t border-white/10">
                      <div className="flex gap-3">
                        <button className="px-4 py-2 bg-cyber-red-500/20 text-cyber-red-500 rounded hover:bg-cyber-red-500/30 transition-all text-sm">
                          View Details
                        </button>
                        <button className="px-4 py-2 bg-cyber-orange-500/20 text-cyber-orange-500 rounded hover:bg-cyber-orange-500/30 transition-all text-sm">
                          Block Campaign
                        </button>
                        <button className="px-4 py-2 bg-cyber-purple-500/20 text-cyber-purple-500 rounded hover:bg-cyber-purple-500/30 transition-all text-sm">
                          Generate Report
                        </button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}