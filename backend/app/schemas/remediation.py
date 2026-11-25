from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, date

class RemediationTaskCreate(BaseModel):
    application_id: str
    component_id: str
    vulnerability_id: str
    title: str
    description: str = ""
    priority: str = "HIGH" # URGENT, HIGH, MEDIUM, LOW
    assigned_team: str = "SecOps AppSec"
    target_resolution_date: Optional[date] = None
    recommended_version: str = ""
    compensating_controls: str = ""

class RemediationTaskUpdate(BaseModel):
    status: Optional[str] = None # OPEN, IN_PROGRESS, AWAITING_VALIDATION, RESOLVED, RISK_ACCEPTED, REOPENED
    assigned_team: Optional[str] = None
    priority: Optional[str] = None
    target_resolution_date: Optional[date] = None
    compensating_controls: Optional[str] = None
    risk_acceptance_justification: Optional[str] = None

class RemediationTaskResponse(BaseModel):
    id: str
    org_id: str
    application_id: str
    application_name: str
    component_id: str
    component_name: str
    component_version: str
    vulnerability_id: str
    vulnerability_severity: str
    title: str
    description: str
    priority: str
    status: str
    assigned_team: str
    target_resolution_date: Optional[date] = None
    recommended_version: str
    verified_in_sbom_id: Optional[str] = None
    compensating_controls: str
    risk_acceptance_justification: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class RemediationVerifyRequest(BaseModel):
    application_id: str
    new_sbom_id: str
    target_vulnerability_id: str

class RemediationVerifyResponse(BaseModel):
    verified: bool
    status: str
    previous_version: str
    current_version: str
    residual_risk: str
    message: str
