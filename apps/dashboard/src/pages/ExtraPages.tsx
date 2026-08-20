import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { ApiEndpoint, AuditLog, ComplianceControl, Dependency, HistorySnapshot, Policy, Regression, Report, Service } from '../types';
import { GateBadge, RiskBadge, SeverityBadge } from '../components/common/Badges';

export const DependenciesPage: React.FC = () => {
  const [items, setItems] = useState<Dependency[]>([]);
  useEffect(() => { api.getDependencies().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Software Bill of Materials (SBOM) & Dependencies</h2>
      <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Package</th>
              <th style={{ padding: '0.85rem 1rem' }}>Version</th>
              <th style={{ padding: '0.85rem 1rem' }}>Ecosystem</th>
              <th style={{ padding: '0.85rem 1rem' }}>Vulnerability Status</th>
              <th style={{ padding: '0.85rem 1rem' }}>Remediation Version</th>
            </tr>
          </thead>
          <tbody>
            {items.map((d) => (
              <tr key={d.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '0.85rem 1rem', fontWeight: 600, color: '#fff' }}>{d.package_name}</td>
                <td style={{ padding: '0.85rem 1rem', fontFamily: 'var(--font-mono)' }}>{d.current_version}</td>
                <td style={{ padding: '0.85rem 1rem' }}>{d.ecosystem}</td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <span style={{ color: d.vulnerability_status === 'VULNERABLE' ? 'var(--color-critical)' : 'var(--color-pass)', fontWeight: 600 }}>
                    {d.vulnerability_status}
                  </span>
                </td>
                <td style={{ padding: '0.85rem 1rem', fontFamily: 'var(--font-mono)' }}>{d.fixed_in_version || 'N/A'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const ServicesPage: React.FC = () => {
  const [items, setItems] = useState<Service[]>([]);
  useEffect(() => { api.getServices().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Discovered Services & Component Architecture</h2>
      <div className="grid grid-cols-2 gap-4">
        {items.map((s) => (
          <div key={s.id} className="glass-card flex flex-col gap-2">
            <div className="flex justify-between items-center">
              <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: '#fff' }}>{s.name}</h3>
              <RiskBadge score={s.risk_score} />
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Framework: {s.framework} ({s.language}) | Exposure: {s.exposure.toUpperCase()}
            </p>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {s.api_count} endpoints | {s.dependency_count} dependencies
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export const ApisPage: React.FC = () => {
  const [items, setItems] = useState<ApiEndpoint[]>([]);
  useEffect(() => { api.getApis().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>API Inventory & Security Posture</h2>
      <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Method & Route</th>
              <th style={{ padding: '0.85rem 1rem' }}>Service</th>
              <th style={{ padding: '0.85rem 1rem' }}>Auth Status</th>
              <th style={{ padding: '0.85rem 1rem' }}>Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '0.85rem 1rem', fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#fff' }}>
                  <span style={{ color: 'var(--color-accent-teal)', marginRight: '0.5rem' }}>{a.method}</span> {a.path}
                </td>
                <td style={{ padding: '0.85rem 1rem' }}>{a.service_name}</td>
                <td style={{ padding: '0.85rem 1rem' }}>
                  <span style={{ color: a.has_auth_missing ? 'var(--color-critical)' : 'var(--color-pass)', fontWeight: 600 }}>
                    {a.has_auth_missing ? 'MISSING AUTH' : 'AUTHENTICATED'}
                  </span>
                </td>
                <td style={{ padding: '0.85rem 1rem' }}><RiskBadge score={a.risk_score} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const HistoryPage: React.FC = () => {
  const [items, setItems] = useState<HistorySnapshot[]>([]);
  useEffect(() => { api.getHistory().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Security Intelligence Timeline History</h2>
      <div className="glass-card flex flex-col gap-3">
        {items.map((h, i) => (
          <div key={i} className="flex justify-between items-center" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
            <div>
              <strong style={{ color: '#fff', fontSize: '0.95rem' }}>Commit {h.commit}</strong>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{h.timestamp}</div>
            </div>
            <div className="flex items-center gap-4">
              <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--color-accent-indigo)' }}>Score {h.score}</span>
              <span style={{ fontSize: '0.8rem', color: 'var(--color-critical)' }}>{h.critical_count} Critical</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export const RegressionsPage: React.FC = () => {
  const [items, setItems] = useState<Regression[]>([]);
  useEffect(() => { api.getRegressions().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Security Regression Monitoring</h2>
      {items.map((r) => (
        <div key={r.id} className="glass-card flex flex-col gap-2" style={{ borderLeft: '4px solid var(--color-critical)' }}>
          <div className="flex justify-between items-center">
            <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>{r.regression_type}</h3>
            <SeverityBadge severity={r.severity} />
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Introduced in commit <code style={{ color: '#fff' }}>{r.introducing_commit}</code> on endpoint {r.affected_endpoint}
          </p>
        </div>
      ))}
    </div>
  );
};

export const PoliciesPage: React.FC = () => {
  const [items, setItems] = useState<Policy[]>([]);
  useEffect(() => { api.getPolicies().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Security Policy Rules & Gates</h2>
      <div className="grid grid-cols-2 gap-4">
        {items.map((p) => (
          <div key={p.id} className="glass-card flex flex-col justify-between gap-3">
            <div>
              <div className="flex justify-between items-center" style={{ marginBottom: '0.5rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>{p.name}</h3>
                <GateBadge status={p.status} />
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{p.description}</p>
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Conditions: {p.conditions.join(', ')}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export const CompliancePage: React.FC = () => {
  const [items, setItems] = useState<ComplianceControl[]>([]);
  useEffect(() => { api.getCompliance().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Compliance Framework Matrix</h2>
      <div className="glass-card flex flex-col gap-3">
        {items.map((c) => (
          <div key={c.id} className="flex justify-between items-center" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '0.75rem' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-accent-teal)', fontWeight: 600 }}>{c.framework}</span>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#fff' }}>{c.control_id}: {c.title}</h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{c.remediation_summary}</p>
            </div>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: c.status === 'PASS' ? 'var(--color-pass)' : 'var(--color-critical)' }}>
              {c.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};

export const ReportsPage: React.FC = () => {
  const [items, setItems] = useState<Report[]>([]);
  useEffect(() => { api.getReports().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Security Audit Reports & Artifacts</h2>
      <div className="grid grid-cols-2 gap-4">
        {items.map((r) => (
          <div key={r.id} className="glass-card flex justify-between items-center">
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>{r.report_type} Export</h3>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Created at {r.created_at}</span>
            </div>
            <button
              onClick={() => alert(`Downloading ${r.report_type} report artifact...`)}
              style={{
                backgroundColor: 'var(--bg-accent)',
                border: '1px solid var(--border-color)',
                color: 'var(--color-accent-teal)',
                padding: '0.4rem 0.8rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                cursor: 'pointer',
              }}
            >
              Download
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

export const AuditPage: React.FC = () => {
  const [items, setItems] = useState<AuditLog[]>([]);
  useEffect(() => { api.getAuditLogs().then(setItems); }, []);
  return (
    <div className="flex flex-col gap-6">
      <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>System Audit Trail</h2>
      <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-color)', backgroundColor: 'var(--bg-secondary)' }}>
              <th style={{ padding: '0.85rem 1rem' }}>Event</th>
              <th style={{ padding: '0.85rem 1rem' }}>Actor</th>
              <th style={{ padding: '0.85rem 1rem' }}>Resource</th>
              <th style={{ padding: '0.85rem 1rem' }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id} style={{ borderBottom: '1px solid var(--border-color)' }}>
                <td style={{ padding: '0.85rem 1rem', fontWeight: 600, color: '#fff' }}>{a.event}</td>
                <td style={{ padding: '0.85rem 1rem' }}>{a.actor}</td>
                <td style={{ padding: '0.85rem 1rem' }}>{a.resource}</td>
                <td style={{ padding: '0.85rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{a.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export const SettingsPage: React.FC = () => (
  <div className="flex flex-col gap-6">
    <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Platform Settings & API Connection</h2>
    <div className="glass-card flex flex-col gap-4" style={{ width: '600px' }}>
      <div className="flex flex-col gap-1">
        <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>FastAPI Base Endpoint URL</label>
        <input
          disabled
          value="http://localhost:8000"
          style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '0.5rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}
        />
      </div>
      <div className="flex flex-col gap-1">
        <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Scan Engine Default Profile</label>
        <select style={{ backgroundColor: 'var(--bg-primary)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '0.5rem', color: '#fff', fontSize: '0.85rem' }}>
          <option value="strict">Strict (Fail on Critical or High)</option>
          <option value="default">Default Security</option>
        </select>
      </div>
    </div>
  </div>
);
