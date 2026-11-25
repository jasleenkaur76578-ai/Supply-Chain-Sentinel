from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class BusinessServiceCreate(BaseModel):
    name: str
    criticality: str = "BUSINESS_OPERATIONAL"
    financial_impact_rating: float = 50000.0
    owner_team: str = "Enterprise Platform Ops"

class BusinessServiceResponse(BaseModel):
    id: str
    name: str
    criticality: str
    financial_impact_rating: float
    owner_team: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ApplicationCreate(BaseModel):
    name: str
    repository_url: str = ""
    environment: str = "PRODUCTION"
    business_criticality: str = "HIGH"
    internet_exposed: bool = False
    business_service_ids: List[str] = []

class ApplicationResponse(BaseModel):
    id: str
    org_id: str
    name: str
    repository_url: str
    environment: str
    business_criticality: str
    internet_exposed: bool
    active_sbom_id: Optional[str] = None
    current_risk_score: float
    created_at: Optional[datetime] = None
    business_services: List[BusinessServiceResponse] = []

    class Config:
        from_attributes = True
