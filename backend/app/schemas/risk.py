from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class RiskScoreBreakdown(BaseModel):
    cvss_component: float
    epss_component: float
    kev_component: float
    criticality_component: float
    exposure_component: float
    depth_attenuation: float
    total_score: float

class ApplicationRiskResponse(BaseModel):
    application_id: str
    application_name: str
    environment: str
    business_criticality: str
    internet_exposed: bool
    overall_score: float
    risk_tier: str
    breakdown: RiskScoreBreakdown
    primary_risk_drivers: List[str]
    critical_vulnerabilities_count: int
    high_vulnerabilities_count: int

class RiskPolicyUpdate(BaseModel):
    cvss_weight: float = 0.25
    epss_weight: float = 0.20
    kev_weight: float = 0.25
    criticality_weight: float = 0.15
    exposure_weight: float = 0.15
