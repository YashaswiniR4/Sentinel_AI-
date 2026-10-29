/**
 * SentinelAI User Security Portal API Service
 * Connects the React User Frontend (Port 5173) to the FastAPI Backend.
 */

import { ROUTES } from '../constants/routes';

const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL)
    ? import.meta.env.VITE_API_BASE_URL.replace(/\/$/, '')
    : 'http://127.0.0.1:8000/api';

const TOKEN_KEY = 'sentinel_user_token';
const USER_INFO_KEY = 'sentinel_user_info';

export function getStoredUserToken() {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredUserToken(token) {
  try {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  } catch {}
}

export function getStoredUserInfo() {
  try {
    const raw = localStorage.getItem(USER_INFO_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function setStoredUserInfo(info) {
  try {
    if (info) {
      localStorage.setItem(USER_INFO_KEY, JSON.stringify(info));
    } else {
      localStorage.removeItem(USER_INFO_KEY);
    }
  } catch {}
}

export function logoutUser() {
  setStoredUserToken(null);
  setStoredUserInfo(null);
}

async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;
  
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  const token = getStoredUserToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers });

  let data = null;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const isAuthLogin = endpoint.includes('/auth/login');
    if (response.status === 401 && !isAuthLogin) {
      logoutUser();
      if (typeof window !== 'undefined' && window.location.hash !== ROUTES.LOGIN) {
        window.location.hash = ROUTES.LOGIN;
      }
      throw new Error('Your session has expired. Please log in again.');
    }

    const errorMsg =
      (data && (data.detail || data.message)) ||
      `HTTP Error ${response.status}: ${response.statusText}`;
    throw new Error(errorMsg);
  }

  return data;
}

export async function loginUser(usernameOrEmail, password) {
  const data = await request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: usernameOrEmail, password }),
  });

  if (data && data.access_token) {
    setStoredUserToken(data.access_token);
    setStoredUserInfo({
      username: data.username,
      name: data.name || data.username,
      email: data.email || usernameOrEmail,
      role: data.role,
      securityScore: data.security_score || 98,
    });
  }
  return data;
}

export async function registerUser({ name, username, email, password }) {
  return await request('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ name, username, email, password }),
  });
}

export async function verifyOtp(email, otp_code) {
  const data = await request('/auth/verify-otp', {
    method: 'POST',
    body: JSON.stringify({ email, otp_code }),
  });

  if (data && data.access_token) {
    setStoredUserToken(data.access_token);
    setStoredUserInfo({
      username: data.username,
      name: data.name || data.username,
      email: data.email || email,
      role: data.role,
      securityScore: data.security_score || 100,
    });
  }
  return data;
}

export async function requestPasswordRecovery(email) {
  return await request('/auth/forgot-password', {
    method: 'POST',
    body: JSON.stringify({ email }),
  });
}

export async function resetPassword(email, otp_code, new_password) {
  return await request('/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify({ email, otp_code, new_password }),
  });
}

export async function simulateUserSecurityEvent(event_type) {
  return await request('/user/simulate-event', {
    method: 'POST',
    body: JSON.stringify({ event_type }),
  });
}

export async function fetchUserSecurityStatus() {
  return await request('/user/security-status');
}

export async function fetchUserActivity() {
  return await request('/user/activity');
}

export async function fetchUserAlerts() {
  return await request('/user/alerts');
}

