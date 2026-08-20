import React, { useEffect, useState } from 'react';
import { GitPullRequest } from 'lucide-react';
import { api } from '../api/client';
import type { AttackPath } from '../types';
import { AttackPathGraph } from '../components/graphs/AttackPathGraph';
import { RiskBadge } from '../components/common/Badges';

export const AttackPaths: React.FC = () => {
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getAttackPaths()
      .then((data) => {
        setPaths(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>Attack Path Analysis Graph</h2>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          Interactive topological graphs mapping entry points to high-value internal database assets and sensitive resources.
        </p>
      </div>

      {loading ? (
        <div style={{ color: 'var(--text-secondary)' }}>Loading attack path topology...</div>
      ) : (
        paths.map((ap) => (
          <div key={ap.id} className="flex flex-col gap-4">
            <div className="glass-card flex items-center justify-between">
              <div className="flex items-center gap-3">
                <GitPullRequest size={20} color="var(--color-critical)" />
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>{ap.title}</h3>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Entry Point: <strong style={{ color: '#fff' }}>{ap.entry_point}</strong> → Target: <strong style={{ color: 'var(--color-critical)' }}>{ap.target_asset}</strong>
                  </span>
                </div>
              </div>
              <RiskBadge score={ap.risk_score} />
            </div>

            {/* Interactive Attack Topology Graph */}
            <AttackPathGraph path={ap} />

            <div className="glass-card" style={{ borderLeft: '4px solid var(--color-pass)' }}>
              <h4 style={{ fontSize: '0.85rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                Attack Path Remediation
              </h4>
              <p style={{ fontSize: '0.85rem', color: '#fff' }}>{ap.remediation}</p>
            </div>
          </div>
        ))
      )}
    </div>
  );
};
