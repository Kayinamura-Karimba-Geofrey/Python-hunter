/* Centralized TypeScript Interfaces for Python Hunter Web Dashboard */

export type SeverityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type GateStatusType = 'PASS' | 'WARN' | 'FAIL';
export type JobStatusType = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export interface User {
  id: string;
  username: string;
  role: string;
  email: string;
}

export interface SystemInfo {
  name: string;
  version: string;
  supported_languages: string[];
  supported_frameworks: string[];
  status: string;
}

export interface DashboardSummary {
  security_score: number;
  previous_score: number;
  score_delta: number;
  risk_level: string;
  gate_status: GateStatusType;
  counts_by_severity: Record<SeverityType, number>;
  new_regressions_count: number;
  total_findings: number;
  total_repositories: number;
  total_scans: number;
  failed_policies_count: number;
  warnings_count: number;
  exceptions_count: number;
}

export interface Finding {
  id: string;
  title: string;
  rule_id: string;
  severity: SeverityType;
  confidence: string;
  risk_score: number;
  exploitability_score: number;
  language: string;
  framework?: string;
  file_path: string;
  line_number: number;
  function_name?: string;
  code_snippet: string;
  description: string;
  remediation_guidance: string;
  why_it_matters: string;
  status: 'NEW' | 'OPEN' | 'FIXED' | 'REOPENED' | 'SUPPRESSED';
  service_name?: string;
  endpoint?: string;
}

export interface Repository {
  id: string;
  name: string;
  provider: 'local' | 'github';
  url_or_path: string;
  default_branch: string;
  last_scan_at: string;
  security_score: number;
  risk_level: string;
  open_findings_count: number;
  status: string;
}

export interface AttackPathNode {
  id: string;
  label: string;
  type: 'internet' | 'api' | 'service' | 'database' | 'asset' | 'external';
  risk_score: number;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  label: string;
  type: 'request' | 'dataflow' | 'trust';
}

export interface AttackPath {
  id: string;
  title: string;
  entry_point: string;
  target_asset: string;
  affected_services: string[];
  risk_score: number;
  exploitability_score: number;
  confidence: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  remediation: string;
}

export interface Dependency {
  id: string;
  package_name: string;
  current_version: string;
  ecosystem: string;
  is_direct: boolean;
  is_production: boolean;
  vulnerability_status: 'SAFE' | 'VULNERABLE';
  vulnerable_versions?: string;
  advisory_id?: string;
  severity?: SeverityType;
  fixed_in_version?: string;
  risk_score: number;
}

export interface Service {
  id: string;
  name: string;
  language: string;
  framework: string;
  exposure: 'public' | 'internal' | 'isolated';
  api_count: number;
  dependency_count: number;
  risk_score: number;
}

export interface ApiEndpoint {
  id: string;
  method: string;
  path: string;
  service_name: string;
  is_authenticated: boolean;
  is_authorized: boolean;
  has_auth_missing: boolean;
  is_sensitive: boolean;
  risk_score: number;
}

export interface HistorySnapshot {
  timestamp: string;
  commit: string;
  score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  new_findings: number;
  fixed_findings: number;
  regressions: number;
}

export interface Regression {
  id: string;
  regression_type: string;
  severity: SeverityType;
  commit: string;
  status: string;
  risk_impact: string;
  previous_state: string;
  current_state: string;
  introducing_commit: string;
  fixing_commit?: string;
  affected_files: string[];
  affected_endpoint?: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  status: GateStatusType;
  conditions: string[];
  affected_findings_count: number;
  exceptions_count: number;
}

export interface ComplianceControl {
  id: string;
  framework: string;
  control_id: string;
  title: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL' | 'NOT_ASSESSED';
  evidence_count: number;
  affected_findings_count: number;
  remediation_summary: string;
}

export interface Report {
  id: string;
  report_type: 'JSON' | 'SARIF' | 'EXECUTIVE_PDF' | 'CSV';
  scan_id: string;
  created_at: string;
  status: string;
  download_url: string;
}

export interface AuditLog {
  id: string;
  event: string;
  actor: string;
  timestamp: string;
  resource: string;
  result: string;
}
