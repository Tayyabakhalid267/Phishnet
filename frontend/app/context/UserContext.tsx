'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface User {
  id?: string;
  userId?: string;
  username: string;
  email: string;
  loginTime: string;
  threatDetections: number;
  lastActivity: string;
}

interface UserContextType {
  user: User | null;
  isAuthenticated: boolean;
  login: (userData: User) => void;
  logout: () => void;
  updateThreatCount: () => void;
  logActivity: (activity: string, details: string) => void;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

export const useUser = () => {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};

interface UserProviderProps {
  children: ReactNode;
}

export const UserProvider: React.FC<UserProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    // Check if user is already logged in
    const savedUser = localStorage.getItem('phishnet_user');
    const isAuth = localStorage.getItem('phishnet_authenticated');
    
    if (savedUser && isAuth === 'true') {
      setUser(JSON.parse(savedUser));
      setIsAuthenticated(true);
    }
  }, []);

  const login = (userData: User) => {
    setUser(userData);
    setIsAuthenticated(true);
    localStorage.setItem('phishnet_user', JSON.stringify(userData));
    localStorage.setItem('phishnet_authenticated', 'true');
    
    // Add user to registered users list if not exists
    const registeredUsers = JSON.parse(localStorage.getItem('phishnet_registered_users') || '[]');
    const userId = (userData as any).id || userData.userId; // Handle both id and userId properties
    const existingUserIndex = registeredUsers.findIndex((u: any) => u.id === userId || u.username === userData.username);
    if (existingUserIndex >= 0) {
      registeredUsers[existingUserIndex] = { ...registeredUsers[existingUserIndex], ...userData, lastActivity: new Date().toISOString() };
    } else {
      registeredUsers.push({ ...userData, id: userId, name: userData.username, role: 'User', registeredAt: new Date().toISOString() });
    }
    localStorage.setItem('phishnet_registered_users', JSON.stringify(registeredUsers));
    
    // Log login activity
    logActivity('User Login', `${userData.username} logged in successfully`);
  };

  const logout = () => {
    if (user) {
      logActivity('User Logout', `${user.username} logged out`);
    }
    
    setUser(null);
    setIsAuthenticated(false);
    localStorage.removeItem('phishnet_user');
    localStorage.removeItem('phishnet_authenticated');
  };

  const updateThreatCount = () => {
    if (user) {
      const updatedUser = {
        ...user,
        threatDetections: user.threatDetections + 1,
        lastActivity: new Date().toISOString()
      };
      setUser(updatedUser);
      localStorage.setItem('phishnet_user', JSON.stringify(updatedUser));
      
      // Update user stats in admin tracking
      const userId = (user as any).id || user.userId;
      if (userId) {
        const userStats = JSON.parse(localStorage.getItem('phishnet_user_stats') || '{}');
        userStats[userId] = {
          username: user.username,
          totalThreats: updatedUser.threatDetections,
          lastActivity: updatedUser.lastActivity,
          loginTime: user.loginTime
        };
        localStorage.setItem('phishnet_user_stats', JSON.stringify(userStats));
      }
    }
  };

  const logActivity = (activity: string, details: string) => {
    const activityLog = JSON.parse(localStorage.getItem('phishnet_user_activity') || '[]');
    const userId = (user as any)?.id || user?.userId || 'anonymous'; // Handle both id and userId properties
    const newActivity = {
      id: Date.now(),
      userId: userId,
      username: user?.username || 'Anonymous',
      type: activity.toLowerCase().replace(/\s+/g, '_'),
      action: activity,
      timestamp: new Date().toISOString(),
      details
    };
    
    activityLog.unshift(newActivity);
    localStorage.setItem('phishnet_user_activity', JSON.stringify(activityLog.slice(0, 100)));
    
    // Also save user-specific activity if user is logged in
    if (user) {
      const userActivityKey = `phishnet_user_activity_${userId}`;
      const userActivity = JSON.parse(localStorage.getItem(userActivityKey) || '[]');
      userActivity.unshift(newActivity);
      localStorage.setItem(userActivityKey, JSON.stringify(userActivity.slice(0, 50)));
      
      // Update user's last activity
      const updatedUser = {
        ...user,
        lastActivity: new Date().toISOString()
      };
      setUser(updatedUser);
      localStorage.setItem('phishnet_user', JSON.stringify(updatedUser));
    }
  };

  return (
    <UserContext.Provider value={{
      user,
      isAuthenticated,
      login,
      logout,
      updateThreatCount,
      logActivity
    }}>
      {children}
    </UserContext.Provider>
  );
};