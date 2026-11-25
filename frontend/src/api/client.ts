import {
  DashboardOverview,
  Application,
  BusinessService,
  Vulnerability,
  PropagationResult,
  RemediationTask,
  Supplier,
  SecurityAlert,
  User,
  AdminOverview,
  AdminUser,
  AuditLogEntry
} from '../types';

const API_BASE = `${(import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')}/api/v1`;

class ApiClient {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem('sentinel_jwt_token');
  }

  setToken(token: string) {
    this.token = token;
    localStorage.setItem('sentinel_jwt_token', token);
  }

  clearToken() {
    this.token = null;
    localStorage.removeItem('sentinel_jwt_token');
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string> || {}),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    if (!(options.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!res.ok) {
      if (res.status === 401 && !endpoint.startsWith('/auth/login') && !endpoint.startsWith('/auth/register')) {
        this.clearToken();
        window.dispatchEvent(new Event('sentinel:unauthorized'));
      }
      let errorMsg = `API Error: ${res.status} ${res.statusText}`;
      try {
        const errorData = await res.json();
        errorMsg = errorData.detail || errorData.message || errorMsg;
      } catch (_) {}
      throw new Error(errorMsg);
    }

    // Check if CSV or raw
    const contentType = res.headers.get('content-type');
    if (contentType && contentType.includes('text/csv')) {
      return (await res.text()) as unknown as T;
    }

    return res.json();
  }

  // Auth
  async login(email: string, password: string): Promise<{ access_token: string; user: User }> {
    const data = await this.request<{ access_token: string; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.access_token);
    return data;
  }

  async register(full_name: string, email: string, password: string): Promise<{ access_token: string; user: User }> {
    const data = await this.request<{ access_token: string; user: User }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ full_name, email, password }),
    });
    this.setToken(data.access_token);
    return data;
  }

  logout() {
    this.clearToken();
  }

  async getMe(): Promise<User> {
    return this.request<User>('/auth/me');
  }

  // Dashboard
  async getDashboardOverview(): Promise<DashboardOverview> {
    return this.request<DashboardOverview>('/dashboard/overview');
  }

  // Assets
  async getApplications(): Promise<Application[]> {
    return this.request<Application[]>('/assets/applications');
  }

  async getApplication(id: string): Promise<Application> {
    return this.request<Application>(`/assets/applications/${id}`);
  }

  async createApplication(appData: Partial<Application> & { business_service_ids?: string[] }): Promise<Application> {
    return this.request<Application>('/assets/applications', {
      method: 'POST',
      body: JSON.stringify(appData),
    });
  }

  async getBusinessServices(): Promise<BusinessService[]> {
    return this.request<BusinessService[]>('/assets/services');
  }

  // SBOM
  async uploadSbom(applicationId: string, file: File): Promise<any> {
    const formData = new FormData();
    formData.append('application_id', applicationId);
    formData.append('file', file);
    return this.request<any>('/sbom/upload', {
      method: 'POST',
      body: formData,
    });
  }

  async getSbomReport(sbomId: string): Promise<any> {
    return this.request<any>(`/sbom/${sbomId}/report`);
  }

  // Vulnerabilities
  async getVulnerabilities(params?: { severity?: string; is_kev?: boolean; search?: string }): Promise<Vulnerability[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.append('severity', params.severity);
    if (params?.is_kev !== undefined) query.append('is_kev', String(params.is_kev));
    if (params?.search) query.append('search', params.search);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return this.request<Vulnerability[]>(`/vulnerabilities${qs}`);
  }

  async getVulnerability(id: string): Promise<Vulnerability> {
    return this.request<Vulnerability>(`/vulnerabilities/${id}`);
  }

  // Graph
  async getApplicationGraph(applicationId: string, maxDepth: number = 5): Promise<{ nodes: any[]; edges: any[] }> {
    return this.request<{ nodes: any[]; edges: any[] }>(`/graph/application/${applicationId}?max_depth=${maxDepth}`);
  }

  // Attack Propagation & Blast Radius
  async analyzePropagation(params: {
    component_name?: string;
    component_version?: string;
    vulnerability_id?: string;
    component_id?: string;
  }): Promise<PropagationResult> {
    return this.request<PropagationResult>('/propagation/analyze', {
      method: 'POST',
      body: JSON.stringify(params),
    });
  }

  // Risk
  async getApplicationRisk(applicationId: string): Promise<any> {
    return this.request<any>(`/risk/applications/${applicationId}`);
  }

  async updateRiskPolicy(policy: {
    cvss_weight: number;
    epss_weight: number;
    kev_weight: number;
    criticality_weight: number;
    exposure_weight: number;
  }): Promise<any> {
    return this.request<any>('/risk/policy', {
      method: 'POST',
      body: JSON.stringify(policy),
    });
  }

  // AI Security Analyst
  async chatWithAnalyst(query: string, conversationId?: string): Promise<{
    response: string;
    grounding_references: Array<{ entity_type: string; entity_id: string; name: string; details?: string }>;
    confidence: string;
    suggested_followups: string[];
  }> {
    return this.request<any>('/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ query, conversation_id: conversationId || 'default' }),
    });
  }

  // Remediation
  async getRemediationTasks(status?: string, priority?: string): Promise<RemediationTask[]> {
    const query = new URLSearchParams();
    if (status) query.append('status', status);
    if (priority) query.append('priority', priority);
    const qs = query.toString() ? `?${query.toString()}` : '';
    return this.request<RemediationTask[]>(`/remediation/tasks${qs}`);
  }

  async createRemediationTask(task: any): Promise<RemediationTask> {
    return this.request<RemediationTask>('/remediation/tasks', {
      method: 'POST',
      body: JSON.stringify(task),
    });
  }

  async updateRemediationTask(taskId: string, update: Partial<RemediationTask>): Promise<any> {
    return this.request<any>(`/remediation/tasks/${taskId}`, {
      method: 'PATCH',
      body: JSON.stringify(update),
    });
  }

  async verifyRemediation(payload: {
    application_id: string;
    new_sbom_id: string;
    target_vulnerability_id: string;
  }): Promise<{
    verified: boolean;
    status: string;
    previous_version: string;
    current_version: string;
    residual_risk: string;
    message: string;
  }> {
    return this.request<any>('/remediation/verify', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // Suppliers
  async getSuppliers(): Promise<Supplier[]> {
    return this.request<Supplier[]>('/suppliers');
  }

  // Alerts
  async getAlerts(): Promise<SecurityAlert[]> {
    return this.request<SecurityAlert[]>('/alerts');
  }

  async acknowledgeAlert(alertId: string): Promise<any> {
    return this.request<any>(`/alerts/${alertId}/acknowledge`, {
      method: 'POST',
    });
  }

  // Reports
  async getExecutiveReport(): Promise<any> {
    return this.request<any>('/reports/executive');
  }

  async exportVulnerabilitiesCsv(): Promise<string> {
    return this.request<string>('/reports/vulnerabilities/export/csv');
  }

  // Administration (Admin Roles Only)
  async getAdminOverview(): Promise<AdminOverview> {
    return this.request<AdminOverview>('/admin/overview');
  }

  async getAdminUsers(): Promise<AdminUser[]> {
    return this.request<AdminUser[]>('/admin/users');
  }

  async updateAdminUser(userId: string, update: { role?: string; is_active?: boolean }): Promise<AdminUser> {
    return this.request<AdminUser>(`/admin/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify(update),
    });
  }

  async getAuditLogs(): Promise<AuditLogEntry[]> {
    return this.request<AuditLogEntry[]>('/admin/audit-logs');
  }
}

export const api = new ApiClient();

export const dashboardApi = {
  getSummary: async () => {
    const ov = await api.getDashboardOverview();
    return {
      ...ov.metrics,
      total_dependencies: ov.metrics.total_unique_dependencies,
      risk_exposure_score: ov.metrics.org_risk_exposure_score,
    };
  },
  getOverview: () => api.getDashboardOverview(),
};

export const reportsApi = {
  getExecutiveSummary: () => api.getExecutiveReport(),
  exportVulnerabilitiesCsv: async () => {
    const csvData = await api.exportVulnerabilitiesCsv();
    return new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
  },
};

export const alertsApi = {
  getAlerts: () => api.getAlerts(),
  acknowledgeAlert: (alertId: string) => api.acknowledgeAlert(alertId),
};
