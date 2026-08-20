import React, { useEffect, useState } from 'react';
import { ArrowDown } from 'lucide-react';
import { api } from '../api/client';
import type { DashboardSummary, SeverityType } from '../types';
import { GateBadge, SeverityBadge } from '../components/common/Badges';

interface DashboardProps {
  onNavigate: (route: string, filter?: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getDashboardSummary()
      .then((data) => {
        setSummary(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div style={{ color: 'var(--text-secondary)' }}>Loading security intelligence metrics...</div>;
  }

  if (error || !summary) {
    return <div style={{ color: 'var(--color-critical)' }}>Failed to load security dashboard: {error}</div>;
  }

  const severities: SeverityType[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

  return (
    <div className="flex flex-col gap-6">
      {/* Top Header Metrics Row */}
      <div className="grid grid-cols-4 gap-4">
        {/* Security Score Card */}
        <div className="glass-card flex flex-col justify-between">
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Security Score
          </span>
          <div className="flex items-baseline gap-3" style={{ margin: '0.75rem 0' }}>
            <span style={{ fontSize: '2.5rem', fontWeight: 800, color: '#ffffff' }}>{summary.security_score}</span>
            <span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/ 100</span>
          </div>
          <div className="flex items-center gap-2" style={{ fontSize: '0.8rem', color: 'var(--color-pass)' }}>
            <ArrowDown size={14} color="var(--color-fail)" />
            <span style={{ color: 'var(--color-pass)' }}>↑ {summary.score_delta} points vs previous scan</span>
          </div>
        </div>

        {/* Security Gate Status */}
        <div className="glass-card flex flex-col justify-between">
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Security Gate
          </span>
          <div style={{ margin: '0.75rem 0' }}>
            <GateBadge status={summary.gate_status} />
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            {summary.failed_policies_count} failed policies | {summary.warnings_count} warnings
          </span>
        </div>

        {/* Total Findings */}
        <div className="glass-card flex flex-col justify-between">
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Total Open Findings
          </span>
          <div className="flex items-baseline gap-2" style={{ margin: '0.75rem 0' }}>
            <span style={{ fontSize: '2.5rem', fontWeight: 800, color: '#ffffff' }}>{summary.total_findings}</span>
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--color-critical)' }}>
            {summary.counts_by_severity.CRITICAL} Critical | {summary.counts_by_severity.HIGH} High
          </span>
        </div>

        {/* Regressions */}
        <div className="glass-card flex flex-col justify-between">
          <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            New Regressions
          </span>
          <div className="flex items-baseline gap-2" style={{ margin: '0.75rem 0' }}>
            <span style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--color-critical)' }}>
              {summary.new_regressions_count}
            </span>
          </div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Detected in latest commit</span>
        </div>
      </div>

      {/* Severity Breakdown Bar */}
      <div className="glass-card flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Vulnerability Distribution by Severity</h3>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Click severity badge to filter findings</span>
        </div>

        <div className="grid grid-cols-5 gap-3">
          {severities.map((sev) => (
            <div
              key={sev}
              onClick={() => onNavigate('/findings', sev)}
              className="glass-card glass-card-interactive flex flex-col items-center justify-center gap-2"
              style={{ padding: '1rem', textAlign: 'center' }}
            >
              <SeverityBadge severity={sev} />
              <span style={{ fontSize: '1.75rem', fontWeight: 700, color: '#ffffff' }}>
                {summary.counts_by_severity[sev] || 0}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Historical Score Sparkline Mock */}
      <div className="glass-card flex flex-col gap-4">
        <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>Security Score Trend (Last 30 Days)</h3>
        <div style={{ height: '140px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', padding: '1rem', display: 'flex', alignItems: 'flex-end', gap: '1.5rem' }}>
          {[65, 68, 70, 72, 75, 78, 84].map((score, i) => (
            <div key={i} className="flex flex-col items-center gap-2" style={{ flexGrow: 1 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{score}</span>
              <div
                style={{
                  width: '100%',
                  height: `${score * 1.2}px`,
                  background: 'linear-gradient(180deg, #6366f1, rgba(99,102,241,0.2))',
                  borderRadius: '4px 4px 0 0',
                }}
              />
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Run #{i + 1}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
