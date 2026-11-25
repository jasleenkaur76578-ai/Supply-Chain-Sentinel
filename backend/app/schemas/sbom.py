from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime

class ComponentResponse(BaseModel):
    id: str
    sbom_id: str
    purl: str
    name: str
    version: str
    ecosystem: str
    license_declared: str
    is_direct: bool
    depth: int
    vulnerability_count: int = 0
    max_severity: Optional[str] = None

    class Config:
        from_attributes = True

class DependencyRelationshipResponse(BaseModel):
    id: str
    parent_component_id: str
    child_component_id: str
    relationship_type: str

    class Config:
        from_attributes = True

class SBOMUploadResponse(BaseModel):
    sbom_id: str
    application_id: str
    format: str
    spec_version: str
    file_name: str
    components_parsed: int
    dependencies_parsed: int
    vulnerabilities_detected: int
    critical_count: int
    parsing_warnings: List[str] = []

class SBOMDetailResponse(BaseModel):
    id: str
    application_id: str
    application_name: str
    format: str
    spec_version: str
    file_name: str
    component_count: int
    dependency_count: int
    is_latest: bool
    created_at: datetime
    components: List[ComponentResponse] = []

    class Config:
        from_attributes = True

class SupplierResponse(BaseModel):
    id: str
    name: str
    contact_email: str
    trust_tier: str
    security_assessment_score: float
    review_status: str
    supplied_components_count: int = 0

    class Config:
        from_attributes = True
