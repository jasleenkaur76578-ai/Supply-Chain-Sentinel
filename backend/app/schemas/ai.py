from pydantic import BaseModel
from typing import Optional, List, Dict, Any

class AIChatRequest(BaseModel):
    query: str
    conversation_id: Optional[str] = "default"

class GroundingReference(BaseModel):
    entity_type: str # VULNERABILITY, APPLICATION, COMPONENT, BUSINESS_SERVICE
    entity_id: str
    name: str
    details: Optional[str] = None

class AIChatResponse(BaseModel):
    response: str
    grounding_references: List[GroundingReference]
    confidence: str
    suggested_followups: List[str]
