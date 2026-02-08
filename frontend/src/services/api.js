/**
 * API Service for HoneyNet Intelligence Platform
 * Handles all HTTP requests to the backend API
 */

import axios from 'axios';

// Base URL from environment or default to localhost
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Create axios instance with default config
const api = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor (add auth tokens here)
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor (handle errors)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      localStorage.removeItem('auth_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

/**
 * Dashboard API calls
 */
export const dashboardAPI = {
  getStats: () => api.get('/dashboard/stats'),
  getTimeline: (hours = 24) => api.get(`/dashboard/timeline?hours=${hours}`),
  getGeographic: () => api.get('/dashboard/geographic'),
};

/**
 * Attacks API calls
 */
export const attacksAPI = {
  getRecent: (limit = 50, minScore = 0) => 
    api.get(`/attacks/recent?limit=${limit}&min_threat_score=${minScore}`),
  
  getDetails: (ip) => api.get(`/attacks/${ip}`),
  
  search: (params) => api.post('/attacks/search', params),
  
  getTopAttackers: (limit = 10, hours = 24) => 
    api.get(`/attacks/top/attackers?limit=${limit}&hours=${hours}`),
  
  getMitreTechniques: (hours = 24) => 
    api.get(`/attacks/mitre/techniques?hours=${hours}`),
};

/**
 * Alerts API calls
 */
export const alertsAPI = {
  getActive: (minSeverity = 'medium') => 
    api.get(`/alerts/active?min_severity=${minSeverity}`),
  
  getDetails: (alertId) => api.get(`/alerts/${alertId}`),
  
  acknowledge: (alertId) => api.post(`/alerts/${alertId}/acknowledge`),
};

/**
 * Intelligence API calls
 */
export const intelligenceAPI = {
  getIOCs: (hours = 24, type = null) => {
    const params = new URLSearchParams({ hours: hours.toString() });
    if (type) params.append('ioc_type', type);
    return api.get(`/intelligence/iocs?${params}`);
  },
  
  getTrends: (days = 7) => api.get(`/intelligence/trends?days=${days}`),
};

/**
 * WebSocket connection for real-time updates
 */
export class AttackFeedWebSocket {
  constructor(onMessage, onError) {
    const wsUrl = API_BASE_URL.replace('http', 'ws');
    this.ws = new WebSocket(`${wsUrl}/ws/attacks`);
    
    this.ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error);
      }
    };
    
    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (onError) onError(error);
    };
    
    this.ws.onclose = () => {
      console.log('WebSocket connection closed');
      // Attempt reconnection after 5 seconds
      setTimeout(() => {
        console.log('Attempting WebSocket reconnection...');
        this.ws = new WebSocket(`${wsUrl}/ws/attacks`);
      }, 5000);
    };
  }
  
  close() {
    if (this.ws) {
      this.ws.close();
    }
  }
}

export default api;
