/* Centralized API Client for Python Hunter Dashboard */

import type {
  ApiEndpoint,
  AttackPath,
  AuditLog,
  ComplianceControl,
  DashboardSummary,
  Dependency,
  Finding,
  HistorySnapshot,
  Policy,
  Regression,
  Report,
  Repository,
  Service,
  SystemInfo,
  User,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

class ApiClient {
  private token: string | null = localStorage.getItem('pyh_token');

  public setToken(token: string | null) {
    this.token = token;
    if (token) {
      localStorage.setItem('pyh_token', token);
    } else {
      localStorage.removeItem('pyh_token');
    }
  }

  public getToken(): string | null {
    return this.token;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Request-ID': crypto.randomUUID(),
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      this.setToken(null);
      window.location.href = '#/login';
      throw new Error('Unauthorized session expired. Please log in again.');
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'An unexpected API error occurred.' }));
      throw new Error(errorData.detail || `HTTP Error ${response.status}`);
    }

    return response.json();
  }

  public async login(username: string, password: string): Promise<{ token: string; user: User }> {
    const data = await this.request<{ token: string; user: User }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    this.setToken(data.token);
    return data;
  }

  public async getSystemInfo(): Promise<SystemInfo> {
    return this.request<SystemInfo>('/api/v1/system');
  }

  public async getDashboardSummary(): Promise<DashboardSummary> {
    return this.request<DashboardSummary>('/api/v1/dashboard/summary');
  }

  public async getRepositories(): Promise<Repository[]> {
    return this.request<Repository[]>('/api/v1/repositories');
  }

  public async createScan(targetPath: string, profile: string = 'strict'): Promise<{ scan_id: string; message: string }> {
    return this.request('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({ target_path: targetPath, profile }),
    });
  }

  public async getFindings(severity?: string, status?: string, search?: string): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    if (status) params.append('status', status);
    if (search) params.append('search', search);
    const queryString = params.toString() ? `?${params.toString()}` : '';
    return this.request<Finding[]>(`/api/v1/findings${queryString}`);
  }

  public async getFindingDetail(id: string): Promise<Finding> {
    return this.request<Finding>(`/api/v1/findings/${id}`);
  }

  public async getAttackPaths(): Promise<AttackPath[]> {
    return this.request<AttackPath[]>('/api/v1/attack-paths');
  }

  public async getDependencies(): Promise<Dependency[]> {
    return this.request<Dependency[]>('/api/v1/dependencies');
  }

  public async getServices(): Promise<Service[]> {
    return this.request<Service[]>('/api/v1/services');
  }

  public async getApis(): Promise<ApiEndpoint[]> {
    return this.request<ApiEndpoint[]>('/api/v1/apis');
  }

  public async getHistory(): Promise<HistorySnapshot[]> {
    return this.request<HistorySnapshot[]>('/api/v1/history');
  }

  public async getRegressions(): Promise<Regression[]> {
    return this.request<Regression[]>('/api/v1/regressions');
  }

  public async getPolicies(): Promise<Policy[]> {
    return this.request<Policy[]>('/api/v1/policies');
  }

  public async getCompliance(): Promise<ComplianceControl[]> {
    return this.request<ComplianceControl[]>('/api/v1/compliance');
  }

  public async getReports(): Promise<Report[]> {
    return this.request<Report[]>('/api/v1/reports');
  }

  public async getAuditLogs(): Promise<AuditLog[]> {
    return this.request<AuditLog[]>('/api/v1/audit');
  }

  public async getPullRequests(): Promise<any[]> {
    return this.request<any[]>('/api/v1/github/pull-requests');
  }

  public async getPullRequestDetail(id: string): Promise<any> {
    return this.request<any>(`/api/v1/github/pull-requests/${id}`);
  }

  public async getWebhookStatus(): Promise<any> {
    return this.request<any>('/api/v1/github/webhooks/status');
  }

  public async getLanguages(language?: string): Promise<any[]> {
    const q = language ? `?language=${encodeURIComponent(language)}` : '';
    return this.request<any[]>(`/api/v1/languages${q}`);
  }

  public async getFrameworks(language?: string): Promise<any[]> {
    const q = language ? `?language=${encodeURIComponent(language)}` : '';
    return this.request<any[]>(`/api/v1/frameworks${q}`);
  }

  public async polyglotScan(workspacePath: string, languages?: string[]): Promise<any> {
    return this.request<any>('/api/v1/languages/polyglot-scan', {
      method: 'POST',
      body: JSON.stringify({ workspace_path: workspacePath, selected_languages: languages }),
    });
  }
}

export const api = new ApiClient();
