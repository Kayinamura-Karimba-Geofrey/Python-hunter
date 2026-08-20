import React, { useState } from 'react';
import {
  Shield,
  Search,
  LayoutDashboard,
  FolderGit2,
  PlayCircle,
  AlertTriangle,
  GitPullRequest,
  Package,
  Server,
  Globe,
  History,
  Activity,
  CheckSquare,
  Award,
  FileText,
  Settings,
  Lock,
  LogOut,
  Bell,
  Command,
} from 'lucide-react';
import type { User } from '../../types';

interface LayoutProps {
  currentRoute: string;
  onNavigate: (route: string) => void;
  user: User | null;
  onLogout: () => void;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  currentRoute,
  onNavigate,
  user,
  onLogout,
  children,
}) => {
  const [showPalette, setShowPalette] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const navSections = [
    {
      title: 'Security',
      items: [
        { id: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
        { id: '/repositories', label: 'Repositories', icon: FolderGit2 },
        { id: '/pull-requests', label: 'Pull Requests', icon: GitPullRequest },
        { id: '/scans', label: 'Scans', icon: PlayCircle },
        { id: '/findings', label: 'Findings', icon: AlertTriangle },
        { id: '/attack-paths', label: 'Attack Paths', icon: GitPullRequest },
      ],
    },
    {
      title: 'Analysis',
      items: [
        { id: '/dependencies', label: 'Dependencies', icon: Package },
        { id: '/services', label: 'Services', icon: Server },
        { id: '/apis', label: 'API Inventory', icon: Globe },
      ],
    },
    {
      title: 'History',
      items: [
        { id: '/history', label: 'Security History', icon: History },
        { id: '/regressions', label: 'Regressions', icon: Activity },
      ],
    },
    {
      title: 'Governance',
      items: [
        { id: '/policies', label: 'Policies', icon: CheckSquare },
        { id: '/compliance', label: 'Compliance', icon: Award },
        { id: '/reports', label: 'Reports', icon: FileText },
      ],
    },
    {
      title: 'Configuration',
      items: [
        { id: '/audit', label: 'Audit Logs', icon: Lock },
        { id: '/settings', label: 'Settings', icon: Settings },
      ],
    },
  ];

  return (
    <div className="flex" style={{ minHeight: '100vh', backgroundColor: 'var(--bg-primary)' }}>
      {/* Sidebar Navigation */}
      <aside
        style={{
          width: '260px',
          backgroundColor: 'var(--bg-secondary)',
          borderRight: '1px solid var(--border-color)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '1.25rem 0.75rem',
          flexShrink: 0,
        }}
      >
        <div className="flex flex-col gap-6">
          {/* Brand Header */}
          <div className="flex items-center gap-3" style={{ padding: '0 0.5rem' }}>
            <div
              style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, #6366f1, #14b8a6)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Shield size={22} color="#fff" />
            </div>
            <div>
              <h1 style={{ fontSize: '1rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#fff' }}>
                PYTHON HUNTER
              </h1>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                Security Platform
              </span>
            </div>
          </div>

          {/* Navigation Groups */}
          <nav className="flex flex-col gap-4">
            {navSections.map((sec) => (
              <div key={sec.title} className="flex flex-col gap-1">
                <span
                  style={{
                    fontSize: '0.68rem',
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.08em',
                    padding: '0 0.75rem 0.25rem 0.75rem',
                  }}
                >
                  {sec.title}
                </span>
                {sec.items.map((item) => {
                  const Icon = item.icon;
                  const active = currentRoute === item.id;
                  return (
                    <button
                      key={item.id}
                      onClick={() => onNavigate(item.id)}
                      className="flex items-center gap-3"
                      style={{
                        padding: '0.55rem 0.75rem',
                        borderRadius: '8px',
                        fontSize: '0.85rem',
                        fontWeight: active ? 600 : 400,
                        color: active ? '#ffffff' : 'var(--text-secondary)',
                        backgroundColor: active ? 'var(--bg-accent)' : 'transparent',
                        border: 'none',
                        textAlign: 'left',
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <Icon size={18} color={active ? 'var(--color-accent-teal)' : 'var(--text-muted)'} />
                      {item.label}
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>

        {/* User Account / Logout */}
        <div style={{ paddingTop: '1rem', borderTop: '1px solid var(--border-color)', margin: '0 0.5rem' }}>
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: '#fff' }}>
                {user ? user.username : 'SecOps User'}
              </span>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                {user ? user.role : 'Security Engineer'}
              </span>
            </div>
            <button
              onClick={onLogout}
              title="Log out"
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                padding: '0.25rem',
              }}
            >
              <LogOut size={18} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex flex-col" style={{ flexGrow: 1, minWidth: 0 }}>
        {/* Top Navbar */}
        <header
          className="flex items-center justify-between"
          style={{
            height: '64px',
            padding: '0 2rem',
            borderBottom: '1px solid var(--border-color)',
            backgroundColor: 'var(--bg-secondary)',
          }}
        >
          {/* Quick Search Palette Trigger */}
          <button
            onClick={() => setShowPalette(true)}
            className="flex items-center gap-3"
            style={{
              backgroundColor: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '0.45rem 1rem',
              color: 'var(--text-muted)',
              fontSize: '0.82rem',
              width: '320px',
              cursor: 'pointer',
            }}
          >
            <Search size={16} />
            <span>Search findings, paths, APIs...</span>
            <span
              style={{
                marginLeft: 'auto',
                fontSize: '0.7rem',
                backgroundColor: 'var(--bg-accent)',
                padding: '0.1rem 0.4rem',
                borderRadius: '4px',
              }}
            >
              Cmd+K
            </span>
          </button>

          {/* Top Nav Right Actions */}
          <div className="flex items-center gap-4">
            <button
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--text-secondary)',
                cursor: 'pointer',
                position: 'relative',
              }}
            >
              <Bell size={20} />
              <span
                style={{
                  position: 'absolute',
                  top: -2,
                  right: -2,
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--color-critical)',
                }}
              />
            </button>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>v1.0.0</span>
          </div>
        </header>

        {/* Page Content Render */}
        <main style={{ padding: '2rem', flexGrow: 1, overflowY: 'auto' }}>{children}</main>
      </div>

      {/* Global Command Palette Modal */}
      {showPalette && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'center',
            paddingTop: '10vh',
            zIndex: 9999,
          }}
          onClick={() => setShowPalette(false)}
        >
          <div
            className="glass-card flex flex-col gap-3"
            style={{ width: '600px', backgroundColor: 'var(--bg-secondary)' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-3" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
              <Command size={20} color="var(--color-accent-teal)" />
              <input
                autoFocus
                placeholder="Type command or search query..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  outline: 'none',
                  color: '#fff',
                  fontSize: '1rem',
                  width: '100%',
                }}
              />
            </div>
            <div className="flex flex-col gap-1">
              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Quick Navigation</span>
              {[
                { label: 'View Security Dashboard', route: '/dashboard' },
                { label: 'Explore Findings Table', route: '/findings' },
                { label: 'View Attack Paths Graph', route: '/attack-paths' },
                { label: 'Check Policy Violations', route: '/policies' },
                { label: 'Run New Security Scan', route: '/scans' },
              ].map((cmd) => (
                <button
                  key={cmd.route}
                  onClick={() => {
                    onNavigate(cmd.route);
                    setShowPalette(false);
                  }}
                  style={{
                    padding: '0.5rem 0.75rem',
                    textAlign: 'left',
                    background: 'transparent',
                    border: 'none',
                    borderRadius: '6px',
                    color: '#fff',
                    cursor: 'pointer',
                    fontSize: '0.85rem',
                  }}
                >
                  {cmd.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
