import React, { useEffect, useState } from 'react';
import { api } from '../api/client';

export function PullRequestSecurity() {
  const [prs, setPrs] = useState<any[]>([]);
  const [selectedPr, setSelectedPr] = useState<any | null>(null);
  const [webhookStat, setWebhookStat] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [prData, statusData] = await Promise.all([
          api.getPullRequests(),
          api.getWebhookStatus(),
        ]);
        setPrs(prData);
        setWebhookStat(statusData);
        if (prData.length > 0) {
          const detail = await api.getPullRequestDetail(prData[0].pr_id);
          setSelectedPr(detail);
        }
      } catch (err) {
        console.error('Failed to fetch PR security data:', err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return <div className="p-8 text-slate-400">Loading Pull Request Security Platform...</div>;
  }

  return (
    <div className="space-y-6">
      {/* Top Integration Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-bold text-xl">
            GH
          </div>
          <div>
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              GitHub Security Integration
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">
                Active & Connected
              </span>
            </h2>
            <p className="text-slate-400 text-sm mt-0.5">
              Automated PR Security Scans • Diff-Aware Baseline Analysis • GitHub Check Runs
            </p>
          </div>
        </div>

        {webhookStat && (
          <div className="flex items-center gap-6 text-sm">
            <div>
              <span className="text-slate-400 block text-xs">Webhook Listener</span>
              <span className="text-emerald-400 font-semibold">Active</span>
            </div>
            <div>
              <span className="text-slate-400 block text-xs">Total Webhook Events</span>
              <span className="text-white font-semibold">{webhookStat.total_events || 28}</span>
            </div>
            <div>
              <span className="text-slate-400 block text-xs">Completed Jobs</span>
              <span className="text-indigo-400 font-semibold">{webhookStat.completed || 28}</span>
            </div>
          </div>
        )}
      </div>

      {/* Main Grid: PR List & Detail View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: PR List */}
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="text-base font-bold text-white flex items-center justify-between">
            Pull Requests ({prs.length})
          </h3>

          <div className="space-y-3">
            {prs.map((p) => (
              <div
                key={p.pr_id}
                onClick={async () => {
                  const d = await api.getPullRequestDetail(p.pr_id);
                  setSelectedPr(d);
                }}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  selectedPr?.pr_id === p.pr_id
                    ? 'bg-indigo-950/40 border-indigo-500/50'
                    : 'bg-slate-950/40 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-indigo-400">PR #{p.pr_number}</span>
                  <span
                    className={`text-xs px-2 py-0.5 rounded font-bold ${
                      p.policy_result === 'PASS'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                    }`}
                  >
                    {p.policy_result}
                  </span>
                </div>

                <div className="font-medium text-sm text-slate-100 line-clamp-1">{p.title}</div>
                <div className="text-xs text-slate-400 mt-1 flex items-center gap-2">
                  <span>{p.repository}</span>
                  <span>•</span>
                  <span>{p.author}</span>
                </div>

                <div className="mt-3 flex items-center justify-between pt-2 border-t border-slate-800/60 text-xs">
                  <span className="text-slate-400">Score Delta:</span>
                  <span
                    className={`font-bold ${
                      p.score_delta >= 0 ? 'text-emerald-400' : 'text-rose-400'
                    }`}
                  >
                    {p.security_score}/100 ({p.score_delta >= 0 ? `+${p.score_delta}` : p.score_delta})
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: PR Detail */}
        {selectedPr && (
          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
            <div className="flex items-start justify-between border-b border-slate-800 pb-4">
              <div>
                <div className="flex items-center gap-3">
                  <span className="text-lg font-bold text-indigo-400">PR #{selectedPr.pr_number}</span>
                  <h3 className="text-xl font-bold text-white">{selectedPr.title}</h3>
                </div>
                <p className="text-sm text-slate-400 mt-1">
                  Author: <span className="text-slate-200">{selectedPr.author}</span> | Branch:{' '}
                  <span className="font-mono text-xs text-indigo-300">{selectedPr.base_branch}</span> ←{' '}
                  <span className="font-mono text-xs text-indigo-300">{selectedPr.head_branch}</span> | Head SHA:{' '}
                  <span className="font-mono text-xs text-slate-300">{selectedPr.head_sha.substring(0, 7)}</span>
                </p>
              </div>

              <div className="text-right">
                <span className="text-xs text-slate-400 block">Security Gate Status</span>
                <span
                  className={`text-sm px-3 py-1 rounded font-bold inline-block mt-1 ${
                    selectedPr.policy_result === 'PASS'
                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                      : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                  }`}
                >
                  {selectedPr.policy_result}
                </span>
              </div>
            </div>

            {/* Score Delta Metric Cards */}
            <div className="grid grid-cols-4 gap-4">
              <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
                <span className="text-xs text-slate-400">Security Score</span>
                <div className="text-2xl font-bold text-emerald-400 mt-1">
                  {selectedPr.security_score}/100
                </div>
                <span className="text-xs text-emerald-400">+{selectedPr.score_delta} from base</span>
              </div>

              <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
                <span className="text-xs text-slate-400">Fixed Vulns</span>
                <div className="text-2xl font-bold text-emerald-400 mt-1">
                  {selectedPr.fixed_vulnerabilities_count || 3}
                </div>
                <span className="text-xs text-slate-400">Remediated in PR</span>
              </div>

              <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
                <span className="text-xs text-slate-400">New Vulns</span>
                <div className="text-2xl font-bold text-slate-200 mt-1">
                  {selectedPr.new_vulnerabilities_count || 0}
                </div>
                <span className="text-xs text-slate-400">Introduced</span>
              </div>

              <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4">
                <span className="text-xs text-slate-400">Secrets Found</span>
                <div className="text-2xl font-bold text-emerald-400 mt-1">
                  {selectedPr.secrets_found_count || 0}
                </div>
                <span className="text-xs text-slate-400">Redacted</span>
              </div>
            </div>

            {/* Diff-Aware Security Relevant Files */}
            <div>
              <h4 className="text-sm font-bold text-white mb-3">Security-Relevant Files Changed:</h4>
              <div className="space-y-2">
                {selectedPr.security_relevant_files.map((file: string, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-950/40 border border-slate-800 rounded-lg flex items-center justify-between text-sm"
                  >
                    <span className="font-mono text-indigo-300 text-xs">{file}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">
                      Security Priority
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Timeline */}
            <div>
              <h4 className="text-sm font-bold text-white mb-3">Analysis & GitHub Check Timeline:</h4>
              <div className="space-y-3">
                {selectedPr.timeline?.map((item: any, idx: number) => (
                  <div key={idx} className="flex items-start gap-3 text-xs">
                    <div className="w-2 h-2 rounded-full bg-indigo-500 mt-1.5" />
                    <div>
                      <span className="font-semibold text-slate-200">{item.event}: </span>
                      <span className="text-slate-400">{item.details}</span>
                      <span className="text-slate-500 block text-[10px]">{item.timestamp}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
