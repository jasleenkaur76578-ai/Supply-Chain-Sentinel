import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Date, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base

def gen_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    application_id = Column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    component_id = Column(String(36), ForeignKey("components.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(String(100), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    priority = Column(String(50), default="HIGH") # URGENT, HIGH, MEDIUM, LOW
    status = Column(String(50), default="OPEN") # OPEN, IN_PROGRESS, AWAITING_VALIDATION, RESOLVED, RISK_ACCEPTED, REOPENED
    assigned_team = Column(String(255), default="SecOps AppSec")
    target_resolution_date = Column(Date, nullable=True)
    recommended_version = Column(String(100), default="")
    verified_in_sbom_id = Column(String(36), nullable=True)
    compensating_controls = Column(Text, default="")
    risk_acceptance_justification = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="remediation_tasks")
    application = relationship("Application", back_populates="remediation_tasks")

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, INFO
    entity_type = Column(String(50), default="VULNERABILITY") # VULNERABILITY, KEV_UPDATE, SBOM_ANOMALY, REMEDIATION_OVERDUE
    entity_id = Column(String(255), default="")
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(36), nullable=True)
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="security_alerts")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String(36), nullable=True)
    action = Column(String(100), nullable=False) # AUTH_LOGIN, SBOM_UPLOAD, REMEDIATION_UPDATE, AI_QUERY, etc.
    target_resource = Column(String(255), default="")
    ip_address = Column(String(45), default="127.0.0.1")
    details = Column(JSON, default={})
    timestamp = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="audit_logs")
