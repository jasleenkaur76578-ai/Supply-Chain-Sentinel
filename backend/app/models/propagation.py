import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Float, Integer, ForeignKey, Text, JSON
from app.database import Base

def gen_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class AttackPropagationAnalysis(Base):
    __tablename__ = "attack_propagation_analyses"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    originating_component_id = Column(String(36), ForeignKey("components.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(String(100), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    affected_application_count = Column(Integer, default=0)
    affected_business_service_count = Column(Integer, default=0)
    blast_radius_score = Column(Float, default=0.0) # 0.0 - 100.0
    propagation_paths = Column(JSON, default=[]) # Serialized paths [App -> intermediate -> pkg]
    confidence_level = Column(String(50), default="HIGH") # HIGH, MEDIUM, HEURISTIC
    risk_factors = Column(JSON, default=[])
    explainable_summary = Column(Text, default="")
    analyzed_at = Column(DateTime, default=utc_now)

class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    application_id = Column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    overall_score = Column(Float, default=0.0)
    severity_breakdown = Column(JSON, default={})
    risk_tier = Column(String(50), default="MEDIUM") # CRITICAL, HIGH, MEDIUM, LOW
    primary_risk_drivers = Column(JSON, default=[])
    assessed_at = Column(DateTime, default=utc_now)
