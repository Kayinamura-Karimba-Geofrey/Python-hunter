import React from 'react';
import { ArrowLeft, Code2, Wrench } from 'lucide-react';
import type { Finding } from '../types';
import { RiskBadge, SeverityBadge } from '../components/common/Badges';

interface FindingDetailProps {
  finding: Finding;
  onBack: () => void;
}

export const FindingDetail: React.FC<FindingDetailProps> = ({ finding, onBack }) => {
  return (
    <div className="flex flex-col gap-6">
      {/* Top Header Navigation */}
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          style={{
            background: 'transparent',
            border: '1px solid var(--border-color)',
            color: 'var(--text-secondary)',
            borderRadius: '6px',
            padding: '0.4rem 0.75rem',
            cursor: 'pointer',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            fontSize: '0.8rem',
          }}
        >
          <ArrowLeft size={16} /> Back to Findings
        </button>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>/ {finding.id}</span>
      </div>

      {/* Main Title & Severity Banner */}
      <div className="glass-card flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <SeverityBadge severity={finding.severity} />
            <RiskBadge score={finding.risk_score} />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {finding.rule_id}
            </span>
          </div>
          <span style={{ fontSize: '0.8rem', color: 'var(--color-warn)', fontWeight: 600 }}>
            STATUS: {finding.status}
          </span>
        </div>

        <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#ffffff' }}>{finding.title}</h2>
        <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{finding.description}</p>
      </div>

      {/* Grid containing Remediation & Code Context */}
      <div className="grid grid-cols-2 gap-6">
        {/* Source Code Context Panel */}
        <div className="glass-card flex flex-col gap-3">
          <div className="flex items-center gap-2" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
            <Code2 size={18} color="var(--color-accent-teal)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Source Location & Code Snippet</h3>
          </div>

          <div style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
            <strong>File:</strong> {finding.file_path} <br />
            <strong>Line:</strong> {finding.line_number} {finding.function_name ? `(${finding.function_name})` : ''}
          </div>

          {/* Vulnerable Code Block */}
          <pre
            style={{
              backgroundColor: '#030712',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '1rem',
              overflowX: 'auto',
              fontSize: '0.82rem',
              color: '#f87171',
            }}
          >
            <code>{finding.code_snippet}</code>
          </pre>
          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Note: Secrets and credentials are automatically redacted by server-side analyzers.
          </span>
        </div>

        {/* Actionable Remediation Guidance */}
        <div className="glass-card flex flex-col gap-4" style={{ borderLeft: '4px solid var(--color-pass)' }}>
          <div className="flex items-center gap-2" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
            <Wrench size={18} color="var(--color-pass)" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Recommended Security Remediation</h3>
          </div>

          <div className="flex flex-col gap-1">
            <h4 style={{ fontSize: '0.82rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Why This Matters</h4>
            <p style={{ fontSize: '0.85rem', color: '#fff' }}>{finding.why_it_matters}</p>
          </div>

          <div className="flex flex-col gap-1">
            <h4 style={{ fontSize: '0.82rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>How to Fix It</h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-pass)' }}>{finding.remediation_guidance}</p>
          </div>
        </div>
      </div>
    </div>
  );
};
