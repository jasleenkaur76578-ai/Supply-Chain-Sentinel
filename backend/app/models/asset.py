import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Float, ForeignKey, Table
from sqlalchemy.orm import relationship
from app.database import Base

def gen_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

# Association table between Applications and BusinessServices
application_services = Table(
    "application_services",
    Base.metadata,
    Column("application_id", String(36), ForeignKey("applications.id", ondelete="CASCADE"), primary_key=True),
    Column("service_id", String(36), ForeignKey("business_services.id", ondelete="CASCADE"), primary_key=True)
)

class BusinessService(Base):
    __tablename__ = "business_services"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    criticality = Column(String(50), nullable=False, default="BUSINESS_OPERATIONAL") # MISSION_CRITICAL, BUSINESS_OPERATIONAL, INTERNAL_SUPPORT, LOW
    financial_impact_rating = Column(Float, default=50000.0) # Estimated hourly disruption cost in USD
    owner_team = Column(String(255), default="Enterprise Platform Ops")
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="business_services")
    applications = relationship("Application", secondary=application_services, back_populates="business_services")

class Application(Base):
    __tablename__ = "applications"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    repository_url = Column(String(1024), default="")
    environment = Column(String(50), default="PRODUCTION") # PRODUCTION, STAGING, DEVELOPMENT, TEST
    business_criticality = Column(String(50), default="HIGH") # CRITICAL, HIGH, MEDIUM, LOW
    internet_exposed = Column(Boolean, default=False)
    active_sbom_id = Column(String(36), nullable=True)
    current_risk_score = Column(Float, default=0.0) # 0.0 - 100.0
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    organization = relationship("Organization", back_populates="applications")
    business_services = relationship("BusinessService", secondary=application_services, back_populates="applications")
    sboms = relationship("SBOMDocument", back_populates="application", cascade="all, delete-orphan")
    remediation_tasks = relationship("RemediationTask", back_populates="application")
