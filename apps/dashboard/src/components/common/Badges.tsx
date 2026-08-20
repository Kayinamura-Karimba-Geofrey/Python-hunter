import React from 'react';
import type { GateStatusType, SeverityType } from '../../types';

interface SeverityBadgeProps {
  severity: SeverityType;
  onClick?: () => void;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, onClick }) => {
  const styles: Record<SeverityType, { color: string; bg: string }> = {
    CRITICAL: { color: 'var(--color-critical)', bg: 'var(--color-critical-bg)' },
    HIGH: { color: 'var(--color-high)', bg: 'var(--color-high-bg)' },
    MEDIUM: { color: 'var(--color-medium)', bg: 'var(--color-medium-bg)' },
    LOW: { color: 'var(--color-low)', bg: 'var(--color-low-bg)' },
    INFO: { color: 'var(--color-info)', bg: 'var(--color-info-bg)' },
  };

  const style = styles[severity] || styles.INFO;

  return (
    <span
      onClick={onClick}
      style={{
        color: style.color,
        backgroundColor: style.bg,
        border: `1px solid ${style.color}40`,
        padding: '0.2rem 0.55rem',
        borderRadius: '6px',
        fontSize: '0.75rem',
        fontWeight: 600,
        letterSpacing: '0.05em',
        textTransform: 'uppercase',
        cursor: onClick ? 'pointer' : 'default',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
      }}
    >
      <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: style.color }} />
      {severity}
    </span>
  );
};

interface GateBadgeProps {
  status: GateStatusType;
}

export const GateBadge: React.FC<GateBadgeProps> = ({ status }) => {
  const styles: Record<GateStatusType, { color: string; bg: string }> = {
    PASS: { color: 'var(--color-pass)', bg: 'var(--color-pass-bg)' },
    WARN: { color: 'var(--color-warn)', bg: 'var(--color-warn-bg)' },
    FAIL: { color: 'var(--color-fail)', bg: 'var(--color-fail-bg)' },
  };

  const style = styles[status] || styles.PASS;

  return (
    <span
      style={{
        color: style.color,
        backgroundColor: style.bg,
        border: `1px solid ${style.color}60`,
        padding: '0.35rem 0.85rem',
        borderRadius: '8px',
        fontSize: '0.85rem',
        fontWeight: 700,
        letterSpacing: '0.05em',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.5rem',
      }}
    >
      {status}
    </span>
  );
};

interface RiskBadgeProps {
  score: number;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ score }) => {
  let color = 'var(--color-pass)';
  let bg = 'var(--color-pass-bg)';
  if (score >= 7.0) {
    color = 'var(--color-critical)';
    bg = 'var(--color-critical-bg)';
  } else if (score >= 4.0) {
    color = 'var(--color-medium)';
    bg = 'var(--color-medium-bg)';
  }

  return (
    <span
      style={{
        color,
        backgroundColor: bg,
        padding: '0.2rem 0.5rem',
        borderRadius: '6px',
        fontSize: '0.75rem',
        fontFamily: 'var(--font-mono)',
        fontWeight: 600,
      }}
    >
      Risk {score.toFixed(1)}
    </span>
  );
};
