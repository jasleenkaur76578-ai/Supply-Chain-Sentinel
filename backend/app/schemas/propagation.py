from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime

class PropagationRequest(BaseModel):
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    vulnerability_id: Optional[str] = None
    component_id: Optional[str] = None

class AffectedApplicationDetail(BaseModel):
    id: str
    name: str
    environment: str
    business_criticality: str
    internet_exposed: bool
    dependency_depth: int
    is_direct: bool
    path_trace: List[str]

class AssociatedServiceDetail(BaseModel):
    id: str
    name: str
    criticality: str
    financial_impact_rating: float
    owner_team: str

class PropagationAnalysisResponse(BaseModel):
    originating_component: str
    vulnerability_id: str
    vulnerability_title: str
    severity: str
    cvss_score: float
    is_kev: bool
    epss_score: float
    blast_radius_score: float
    affected_applications_count: int
    affected_applications: List[AffectedApplicationDetail]
    associated_business_services: List[AssociatedServiceDetail]
    total_hourly_disruption_exposure: float
    risk_factors: List[str]
    confidence_level: str
    explainable_summary: str
    recommended_actions: List[str]
    propagation_paths: List[Dict[str, Any]]
