import React, { useEffect, useState } from 'react';
import { Search, Filter, Eye } from 'lucide-react';
import { api } from '../api/client';
import type { Finding } from '../types';
import { RiskBadge, SeverityBadge } from '../components/common/Badges';

interface FindingsProps {
  initialSeverity?: string;
  onSelectFinding: (finding: Finding) => void;
}

export const Findings: React.FC<FindingsProps> = ({ initialSeverity, onSelectFinding }) => {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>(initialSeverity || '');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api
      .getFindings(severityFilter || undefined, undefined, searchQuery || undefined)
      .then((data) => {
        setFindings(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [severityFilter, searchQuery]);

  return (
    <div className="flex flex-col gap-6">
      {/* Header & Filter Control Bar */}
      <div className="flex items-center justify-between">
        <div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Security Findings Inventory</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Real-time security vulnerabilities identified across analyzed source code repositories.
          </p>
        </div>
      </div>

      <div className="glass-card flex items-center justify-between gap-4">
        {/* Search input */}
        <div className="flex items-center gap-2" style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: '8px', padding: '0.4rem 0.8rem', width: '360px' }}>
          <Search size={16} color="var(--text-muted)" />
          <input
            placeholder="Search by title, rule ID, or file..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ background: 'transparent', border: 'none', outline: 'none', color: '#fff', fontSize: '0.85rem', width: '100%' }}
          />
        </div>

        {/* Severity Filter pills */}
        <div className="flex items-center gap-2">
          <Filter size={16} color="var(--text-muted)" />
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Severity:</span>
          {['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev || 'ALL'}
              onClick={() => setSeverityFilter(sev)}
              style={{
                backgroundColor: severityFilter === sev ? 'var(--bg-accent)' : 'transparent',
                border: severityFilter === sev ? '1px solid var(--border-color-hover)' : '1px solid transparent',
                color: severityFilter === sev ? '#fff' : 'var(--text-secondary)',
                borderRadius: '6px',
                padding: '0.25rem 0.6rem',
                fontSize: '0.75rem',
                cursor: 'pointer',
              }}
            >
              {sev || 'ALL'}
            </button>
          ))}
        </div>
      </div>

      {/* Findings Table */}
      <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
              <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)', fontWeight: 600 }}>Severity</th>
              <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)', fontWeight: 600 }}>Finding Title & Rule</th>
              <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)', fontWeight: 600 }}>Risk</th>
              <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)', fontWeight: 600 }}>Location</th>
              <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)', fontWeight: 600 }}>Status</th>
              <th style={{ padding: '0.85rem 1rem', color: 'var(--text-muted)', fontWeight: 600, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Loading findings...
                </td>
              </tr>
            ) : findings.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  No security findings matching current filters.
                </td>
              </tr>
            ) : (
              findings.map((f) => (
                <tr key={f.id} style={{ borderBottom: '1px solid var(--border-color)', transition: 'background 0.15s ease' }}>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <div className="flex flex-col">
                      <strong style={{ color: '#fff' }}>{f.title}</strong>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{f.rule_id}</span>
                    </div>
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <RiskBadge score={f.risk_score} />
                  </td>
                  <td style={{ padding: '0.85rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    {f.file_path}:{f.line_number}
                  </td>
                  <td style={{ padding: '0.85rem 1rem' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--color-warn)' }}>{f.status}</span>
                  </td>
                  <td style={{ padding: '0.85rem 1rem', textAlign: 'right' }}>
                    <button
                      onClick={() => onSelectFinding(f)}
                      style={{
                        background: 'transparent',
                        border: '1px solid var(--border-color)',
                        color: 'var(--color-accent-teal)',
                        padding: '0.25rem 0.6rem',
                        borderRadius: '6px',
                        fontSize: '0.75rem',
                        cursor: 'pointer',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                      }}
                    >
                      <Eye size={14} /> Details
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
