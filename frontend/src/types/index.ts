export interface User {
  id: string;
  email: string;
  full_name: string;
  role: 'super_admin' | 'org_admin' | 'security_analyst' | 'security_engineer' | 'read_only_exec' | 'secops_lead';
  org_id?: string;
  organization_id?: string;
  org_name?: string;
  is_active?: boolean;
  last_login?: string;
  created_at?: string;
}

export interface BusinessService {
  id: string;
  name: string;
  criticality: 'MISSION_CRITICAL' | 'BUSINESS_OPERATIONAL' | 'INTERNAL_SUPPORT' | 'LOW';
  financial_impact_rating: number;
  owner_team: string;
  created_at?: string;
}

export interface Application {
  id: string;
  org_id: string;
  name: string;
  repository_url: string;
  environment: 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT' | 'TEST';
  business_criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  internet_exposed: boolean;
  active_sbom_id?: string;
  current_risk_score: number;
  created_at?: string;
  business_services: BusinessService[];
}

export interface Component {
  id: string;
  sbom_id: string;
  purl: string;
  name: string;
  version: string;
  ecosystem: string;
  license_declared: string;
  is_direct: boolean;
  depth: number;
  vulnerability_count?: number;
  max_severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
}

export interface Vulnerability {
  id: string;
  source: string;
  title: string;
  summary: string;
  details: string;
  cvss_v3_score: number;
  cvss_v3_vector: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  epss_score: number;
  epss_percentile: number;
  is_cisa_kev: boolean;
  cisa_kev_due_date?: string;
  affected_packages?: any[];
  published_at?: string;
  last_modified_at?: string;
  affected_components_count?: number;
  affected_applications?: string[];
}

export interface OverviewMetrics {
  total_assets: number;
  total_unique_dependencies: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  known_exploited_vulnerabilities: number;
  affected_applications: number;
  vulnerable_suppliers: number;
  org_risk_exposure_score: number;
  remediation_completion_rate: number;
  last_intelligence_sync: string;
}

export type DashboardSummary = OverviewMetrics & {
  total_dependencies?: number;
  risk_exposure_score?: number | string;
};

export interface UrgentAttentionFinding {
  id: string;
  cve_id: string;
  package: string;
  installed_version: string;
  severity: string;
  cvss: number;
  is_kev: boolean;
  epss_score: number;
  affected_apps: string[];
  critical_services: string[];
}

export interface RiskTrendPoint {
  date: string;
  risk_score: number;
  critical_count: number;
}

export interface DashboardOverview {
  metrics: OverviewMetrics;
  severity_distribution: Record<string, number>;
  risk_trends: RiskTrendPoint[];
  urgent_attention_findings: UrgentAttentionFinding[];
  remediation_progress: {
    open: number;
    in_progress: number;
    resolved: number;
  };
  top_vulnerable_dependencies: Array<{
    package: string;
    version: string;
    ecosystem: string;
    vuln_count: number;
    highest_severity: string;
    highest_cvss: number;
    has_kev: boolean;
  }>;
  intelligence_source_health: Record<string, {
    name: string;
    status: string;
    last_sync: string;
    latency_ms?: number;
    entries_count?: number;
  }>;
}

export interface PropagationResult {
  originating_component: string;
  vulnerability_id: string;
  vulnerability_title: string;
  severity: string;
  cvss_score: number;
  is_kev: boolean;
  epss_score: number;
  blast_radius_score: number;
  affected_applications_count: number;
  affected_applications: Array<{
    id: string;
    name: string;
    environment: string;
    business_criticality: string;
    internet_exposed: boolean;
    dependency_depth: number;
    is_direct: boolean;
    path_trace: string[];
  }>;
  associated_business_services: Array<{
    id: string;
    name: string;
    criticality: string;
    financial_impact_rating: number;
    owner_team: string;
  }>;
  total_hourly_disruption_exposure: number;
  risk_factors: string[];
  confidence_level: string;
  explainable_summary: string;
  recommended_actions: string[];
  propagation_paths: Array<{
    application: string;
    environment: string;
    is_direct: boolean;
    depth: number;
    path: string[];
  }>;
}

export interface RemediationTask {
  id: string;
  org_id: string;
  application_id: string;
  application_name: string;
  component_id: string;
  component_name: string;
  component_version: string;
  vulnerability_id: string;
  vulnerability_severity: string;
  title: string;
  description: string;
  priority: 'URGENT' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'OPEN' | 'IN_PROGRESS' | 'AWAITING_VALIDATION' | 'RESOLVED' | 'RISK_ACCEPTED' | 'REOPENED';
  assigned_team: string;
  target_resolution_date?: string;
  recommended_version: string;
  verified_in_sbom_id?: string;
  compensating_controls: string;
  risk_acceptance_justification: string;
  created_at: string;
  updated_at: string;
}

export interface Supplier {
  id: string;
  name: string;
  contact_email: string;
  trust_tier: 'TIER_1_VERIFIED' | 'TIER_2_STANDARD' | 'TIER_3_UNVERIFIED' | 'HIGH_RISK';
  security_assessment_score: number;
  review_status: string;
  supplied_components_count: number;
}

export interface SecurityAlert {
  id: string;
  org_id: string;
  title: string;
  message: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
  entity_type: string;
  entity_id: string;
  is_acknowledged: boolean;
  acknowledged_by?: string;
  created_at: string;
}

export interface AdminOverview {
  environment: string;
  database_engine: string;
  total_users: number;
  active_users: number;
  total_applications: number;
  total_sboms: number;
  total_vulnerabilities: number;
  total_audit_logs: number;
  unacknowledged_alerts: number;
  docs_enabled: boolean;
}

export interface AdminUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
  org_id: string;
  is_active: boolean;
  last_login?: string;
  created_at?: string;
}

export interface AuditLogEntry {
  id: string;
  action: string;
  user_id?: string;
  user_email: string;
  target_resource: string;
  details: Record<string, any>;
  timestamp?: string;
}
