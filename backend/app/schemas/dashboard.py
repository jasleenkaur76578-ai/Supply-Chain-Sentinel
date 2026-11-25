from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class OverviewMetrics(BaseModel):
    total_assets: int
    total_unique_dependencies: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    known_exploited_vulnerabilities: int
    affected_applications: int
    vulnerable_suppliers: int
    org_risk_exposure_score: float
    remediation_completion_rate: float
    last_intelligence_sync: datetime

class UrgentAttentionFinding(BaseModel):
    id: str
    cve_id: str
    package: str
    installed_version: str
    severity: str
    cvss: float
    is_kev: bool
    epss_score: float
    affected_apps: List[str]
    critical_services: List[str]

class RiskTrendPoint(BaseModel):
    date: str
    risk_score: float
    critical_count: int

class DashboardOverviewResponse(BaseModel):
    metrics: OverviewMetrics
    severity_distribution: Dict[str, int]
    risk_trends: List[RiskTrendPoint]
    urgent_attention_findings: List[UrgentAttentionFinding]
    remediation_progress: Dict[str, int]
    top_vulnerable_dependencies: List[Dict[str, Any]]
    intelligence_source_health: Dict[str, Dict[str, Any]]
