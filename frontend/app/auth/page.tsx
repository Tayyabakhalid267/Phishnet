'use client';

import { useState, useEffect } from 'react';
import { Shield, Eye, EyeOff, User, Lock, Mail, UserPlus, LogIn, Brain, Target } from 'lucide-react';

export default function AuthPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const [mounted, setMounted] = useState(false);

  // Fix hydration issue
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="text-white mt-4">Loading...</p>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      
      // Store user data in localStorage for demo purposes
      const timestamp = new Date().toISOString();
      const userId = `user_${formData.username}_${Date.now()}`;
      const userData = {
        id: userId,
        username: formData.username,
        name: formData.username,
        email: formData.email,
        role: 'User',
        loginTime: timestamp,
        threatDetections: 0,
        lastActivity: timestamp,
        registeredAt: timestamp
      };

      localStorage.setItem('phishnet_user', JSON.stringify(userData));
      localStorage.setItem('phishnet_authenticated', 'true');
      
      // Handle user registration - add to registered users list
      if (!isLogin) {
        const registeredUsers = JSON.parse(localStorage.getItem('phishnet_registered_users') || '[]');
        // Check if user already exists
        const existingUser = registeredUsers.find((user: any) => user.username === formData.username || user.email === formData.email);
        if (!existingUser) {
          registeredUsers.push(userData);
          localStorage.setItem('phishnet_registered_users', JSON.stringify(registeredUsers));
        }
      } else {
        // For login, update existing user or add if not found
        const registeredUsers = JSON.parse(localStorage.getItem('phishnet_registered_users') || '[]');
        const userIndex = registeredUsers.findIndex((user: any) => user.username === formData.username);
        if (userIndex >= 0) {
          registeredUsers[userIndex] = { ...registeredUsers[userIndex], ...userData, lastActivity: timestamp };
        } else {
          registeredUsers.push(userData);
        }
        localStorage.setItem('phishnet_registered_users', JSON.stringify(registeredUsers));
      }
      
      // Add to user activity log for admin panel (using consistent key)
      const activityLog = JSON.parse(localStorage.getItem('phishnet_user_activity') || '[]');
      activityLog.unshift({
        id: Date.now(),
        userId: userData.id,
        username: userData.username,
        type: isLogin ? 'user_login' : 'user_registration',
        timestamp: new Date().toISOString(),
        details: `${userData.username} ${isLogin ? 'logged in' : 'registered'} successfully`,
        action: isLogin ? 'User Login' : 'User Registration'
      });
      localStorage.setItem('phishnet_user_activity', JSON.stringify(activityLog.slice(0, 100)));

      // Also save user-specific activity
      const userActivityKey = `phishnet_user_activity_${userData.id}`;
      const userActivity = JSON.parse(localStorage.getItem(userActivityKey) || '[]');
      userActivity.unshift({
        id: Date.now(),
        type: isLogin ? 'user_login' : 'user_registration',
        timestamp: new Date().toISOString(),
        details: isLogin ? 'Successfully logged in' : 'Account created successfully',
        action: isLogin ? 'Login' : 'Registration'
      });
      localStorage.setItem(userActivityKey, JSON.stringify(userActivity.slice(0, 50)));

      // Redirect to main dashboard
      window.location.href = '/';
    } catch (error) {
      console.error('Authentication error:', error);
      alert('Authentication failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-red-900 to-black text-white relative overflow-hidden">
      {/* Animated Background Effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-red-500 rounded-full opacity-20 animate-pulse"></div>
        <div className="absolute top-1/2 -left-32 w-64 h-64 bg-purple-500 rounded-full opacity-10 animate-bounce"></div>
        <div className="absolute bottom-20 right-20 w-32 h-32 bg-blue-500 rounded-full opacity-15 animate-ping"></div>
        
        {/* Matrix-style falling code effect */}
        {mounted && (
          <div className="absolute inset-0 opacity-10">
            {Array.from({ length: 20 }).map((_, i) => {
              // Fixed positions to prevent hydration mismatch
              const positions = [
                { left: 10, top: 15, delay: 0 },
                { left: 25, top: 30, delay: 0.5 },
                { left: 40, top: 10, delay: 1 },
                { left: 55, top: 45, delay: 1.5 },
                { left: 70, top: 20, delay: 2 },
                { left: 85, top: 35, delay: 2.5 },
                { left: 15, top: 60, delay: 0.2 },
                { left: 30, top: 75, delay: 0.7 },
                { left: 45, top: 55, delay: 1.2 },
                { left: 60, top: 80, delay: 1.7 },
                { left: 75, top: 65, delay: 2.2 },
                { left: 90, top: 70, delay: 2.7 },
                { left: 20, top: 90, delay: 0.3 },
                { left: 35, top: 5, delay: 0.8 },
                { left: 50, top: 25, delay: 1.3 },
                { left: 65, top: 40, delay: 1.8 },
                { left: 80, top: 85, delay: 2.3 },
                { left: 5, top: 50, delay: 0.1 },
                { left: 95, top: 95, delay: 2.9 },
                { left: 12, top: 72, delay: 0.4 }
              ];
              
              const pos = positions[i % positions.length];
              const codes = ['01001', '11010', 'NULL', 'AI', '0xFF', 'SCAN', 'NET', 'SEC', '404', 'EOF'];
              
              return (
                <div
                  key={i}
                  className="absolute text-green-400 font-mono text-xs animate-pulse"
                  style={{
                    left: `${pos.left}%`,
                    top: `${pos.top}%`,
                    animationDelay: `${pos.delay}s`
                  }}
                >
                  {codes[i % codes.length]}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="relative z-10 flex items-center justify-center min-h-screen p-4">
        <div className="w-full max-w-md">
          {/* Logo Header */}
          <div className="text-center mb-8">
            <div className="flex justify-center items-center gap-4 mb-6">
              <Shield className="w-16 h-16 text-red-500 animate-pulse drop-shadow-lg" />
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-red-500 via-red-400 to-red-300 bg-clip-text text-transparent">
                  PHISHNET AI
                </h1>
                <p className="text-gray-400 text-sm">Enterprise Security Platform</p>
              </div>
              <Brain className="w-16 h-16 text-red-500 animate-pulse drop-shadow-lg" />
            </div>
            <div className="flex justify-center gap-2 mb-6">
              <span className="bg-red-600 text-white px-2 py-1 rounded-full text-xs font-bold">SECURE</span>
              <span className="bg-blue-600 text-white px-2 py-1 rounded-full text-xs font-bold">AI-POWERED</span>
              <span className="bg-green-600 text-white px-2 py-1 rounded-full text-xs font-bold">ENTERPRISE</span>
            </div>
          </div>

          {/* Auth Form Card */}
          <div className="bg-gray-800/80 backdrop-blur-lg p-8 rounded-2xl border border-gray-700 shadow-2xl">
            {/* Tab Switcher */}
            <div className="flex mb-8 bg-gray-700/50 p-1 rounded-lg">
              <button
                onClick={() => setIsLogin(true)}
                className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-md font-bold transition-all ${
                  isLogin 
                    ? 'bg-red-600 text-white shadow-lg' 
                    : 'text-gray-400 hover:text-white hover:bg-gray-600/50'
                }`}
              >
                <LogIn className="w-5 h-5" />
                Login
              </button>
              <button
                onClick={() => setIsLogin(false)}
                className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-md font-bold transition-all ${
                  !isLogin 
                    ? 'bg-red-600 text-white shadow-lg' 
                    : 'text-gray-400 hover:text-white hover:bg-gray-600/50'
                }`}
              >
                <UserPlus className="w-5 h-5" />
                Register
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Username Field */}
              <div>
                <label className="block text-sm font-bold mb-2 text-gray-300">
                  <User className="w-4 h-4 inline mr-2" />
                  Username
                </label>
                <input
                  type="text"
                  name="username"
                  value={formData.username}
                  onChange={handleInputChange}
                  required
                  className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-red-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-all"
                  placeholder="Enter your username"
                />
              </div>

              {/* Email Field (Register only) */}
              {!isLogin && (
                <div>
                  <label className="block text-sm font-bold mb-2 text-gray-300">
                    <Mail className="w-4 h-4 inline mr-2" />
                    Email Address
                  </label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    required={!isLogin}
                    className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-red-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-all"
                    placeholder="Enter your email address"
                  />
                </div>
              )}

              {/* Password Field */}
              <div>
                <label className="block text-sm font-bold mb-2 text-gray-300">
                  <Lock className="w-4 h-4 inline mr-2" />
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    required
                    className="w-full px-4 py-3 pr-12 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-red-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-all"
                    placeholder="Enter your password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {/* Confirm Password (Register only) */}
              {!isLogin && (
                <div>
                  <label className="block text-sm font-bold mb-2 text-gray-300">
                    <Lock className="w-4 h-4 inline mr-2" />
                    Confirm Password
                  </label>
                  <input
                    type={showPassword ? "text" : "password"}
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleInputChange}
                    required={!isLogin}
                    className="w-full px-4 py-3 bg-gray-700/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:border-red-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 transition-all"
                    placeholder="Confirm your password"
                  />
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-4 bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white font-bold rounded-lg transition-all transform hover:scale-105 hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
              >
                {isLoading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    Processing...
                  </>
                ) : (
                  <>
                    {isLogin ? <LogIn className="w-5 h-5" /> : <UserPlus className="w-5 h-5" />}
                    {isLogin ? 'Login to PHISHNET' : 'Create Account'}
                  </>
                )}
              </button>
            </form>

            {/* Demo Accounts */}
            <div className="mt-6 p-4 bg-blue-900/20 border border-blue-700/50 rounded-lg">
              <h4 className="text-blue-400 font-bold mb-2 flex items-center gap-2">
                <Target className="w-4 h-4" />
                Quick Demo Access
              </h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <button
                  onClick={() => setFormData({ ...formData, username: 'Mubashar', password: 'Mubashar9266' })}
                  className="bg-blue-600 hover:bg-blue-700 px-2 py-1 rounded text-white transition-colors"
                >
                  👑 Admin Demo
                </button>
                <button
                  onClick={() => setFormData({ ...formData, username: 'analyst', password: 'analyst123' })}
                  className="bg-green-600 hover:bg-green-700 px-2 py-1 rounded text-white transition-colors"
                >
                  📊 Analyst Demo
                </button>
                <button
                  onClick={() => setFormData({ ...formData, username: 'security', password: 'security123' })}
                  className="bg-purple-600 hover:bg-purple-700 px-2 py-1 rounded text-white transition-colors"
                >
                  🔒 Security Demo
                </button>
                <button
                  onClick={() => setFormData({ ...formData, username: 'guest', password: 'guest123' })}
                  className="bg-gray-600 hover:bg-gray-700 px-2 py-1 rounded text-white transition-colors"
                >
                  👤 Guest Demo
                </button>
              </div>
            </div>

            {/* Footer Links */}
            <div className="mt-6 text-center text-sm text-gray-400">
              <p>Enterprise-grade cybersecurity platform</p>
              <p className="mt-1">
                <span className="text-red-400">●</span> Real-time threat detection
                <span className="text-blue-400 ml-3">●</span> AI-powered analysis
                <span className="text-green-400 ml-3">●</span> Advanced reporting
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}