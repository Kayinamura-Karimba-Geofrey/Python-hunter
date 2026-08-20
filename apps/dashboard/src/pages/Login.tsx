import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import { api } from '../api/client';
import type { User } from '../types';

interface LoginProps {
  onLoginSuccess: (user: User) => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await api.login(username, password);
      onLoginSuccess(res.user);
    } catch (err: any) {
      setError(err.message || 'Login failed');
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--bg-primary)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1rem',
      }}
    >
      <form
        onSubmit={handleSubmit}
        className="glass-card flex flex-col gap-6"
        style={{ width: '400px', backgroundColor: 'var(--bg-secondary)' }}
      >
        <div className="flex flex-col items-center gap-2" style={{ textAlign: 'center' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={28} color="#fff" />
          </div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#fff' }}>Python Hunter Platform</h1>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Sign in to Security Intelligence Dashboard</span>
        </div>

        {error && (
          <div style={{ color: 'var(--color-critical)', fontSize: '0.8rem', textAlign: 'center' }}>
            {error}
          </div>
        )}

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Username</label>
            <input
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. secops"
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.55rem 0.75rem',
                color: '#fff',
                fontSize: '0.85rem',
              }}
            />
          </div>

          <div className="flex flex-col gap-1">
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Password</label>
            <input
              required
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              style={{
                backgroundColor: 'var(--bg-primary)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.55rem 0.75rem',
                color: '#fff',
                fontSize: '0.85rem',
              }}
            />
          </div>
        </div>

        <button
          type="submit"
          style={{
            backgroundColor: 'var(--color-accent-indigo)',
            color: '#fff',
            border: 'none',
            borderRadius: '8px',
            padding: '0.65rem',
            fontWeight: 600,
            fontSize: '0.9rem',
            cursor: 'pointer',
          }}
        >
          Authenticate Session
        </button>
      </form>
    </div>
  );
};
