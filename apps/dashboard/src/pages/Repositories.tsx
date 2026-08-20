import React, { useEffect, useState } from 'react';
import { FolderGit2, Plus, Play } from 'lucide-react';
import { api } from '../api/client';
import type { Repository } from '../types';
import { RiskBadge } from '../components/common/Badges';

interface RepositoriesProps {
  onNavigate: (route: string) => void;
}

export const Repositories: React.FC<RepositoriesProps> = ({ onNavigate }) => {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [targetInput, setTargetInput] = useState('');

  useEffect(() => {
    api
      .getRepositories()
      .then((data) => {
        setRepos(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const handleAddRepo = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput) return;
    await api.createScan(targetInput, 'strict');
    setShowAddModal(false);
    onNavigate('/scans');
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Monitored Repositories & Workspaces</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Inventory of registered local filesystem projects and GitHub repositories.
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          style={{
            backgroundColor: 'var(--color-accent-indigo)',
            color: '#fff',
            border: 'none',
            borderRadius: '8px',
            padding: '0.55rem 1rem',
            fontSize: '0.85rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          <Plus size={16} /> Register Repository
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {loading ? (
          <div style={{ color: 'var(--text-secondary)' }}>Loading repositories...</div>
        ) : (
          repos.map((repo) => (
            <div key={repo.id} className="glass-card flex flex-col justify-between gap-4">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <FolderGit2 size={24} color={repo.provider === 'github' ? '#a855f7' : '#14b8a6'} />
                  <div>
                    <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>{repo.name}</h3>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {repo.provider.toUpperCase()} | Branch: {repo.default_branch}
                    </span>
                  </div>
                </div>
                <RiskBadge score={repo.security_score >= 80 ? 2.0 : 8.0} />
              </div>

              <div className="flex items-center justify-between" style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
                <div className="flex flex-col">
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Security Score</span>
                  <strong style={{ fontSize: '1.1rem', color: '#fff' }}>{repo.security_score} / 100</strong>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      api.createScan(repo.url_or_path, 'strict');
                      onNavigate('/scans');
                    }}
                    style={{
                      backgroundColor: 'var(--bg-accent)',
                      border: '1px solid var(--border-color)',
                      color: '#fff',
                      padding: '0.35rem 0.75rem',
                      borderRadius: '6px',
                      fontSize: '0.78rem',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                    }}
                  >
                    <Play size={14} color="var(--color-pass)" /> Trigger Scan
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Add Repository Modal */}
      {showAddModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 999,
          }}
          onClick={() => setShowAddModal(false)}
        >
          <form
            onSubmit={handleAddRepo}
            className="glass-card flex flex-col gap-4"
            style={{ width: '450px', backgroundColor: 'var(--bg-secondary)' }}
            onClick={(e) => e.stopPropagation()}
          >
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>Register New Repository Target</h3>
            <div className="flex flex-col gap-1">
              <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Target Path or GitHub Repo URL</label>
              <input
                required
                placeholder="e.g. /path/to/project OR https://github.com/org/repo"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                style={{
                  backgroundColor: 'var(--bg-primary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  padding: '0.5rem 0.75rem',
                  color: '#fff',
                  fontSize: '0.85rem',
                }}
              />
            </div>
            <div className="flex justify-between" style={{ marginTop: '0.5rem' }}>
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                style={{
                  backgroundColor: 'var(--color-accent-indigo)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.45rem 1rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Register & Start Scan
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
