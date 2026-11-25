import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

def gen_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True)
    risk_policy = Column(JSON, default={
        "weights": {
            "cvss": 0.25,
            "epss": 0.20,
            "cisa_kev": 0.25,
            "criticality": 0.15,
            "exposure": 0.15
        }
    })
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    applications = relationship("Application", back_populates="organization", cascade="all, delete-orphan")
    business_services = relationship("BusinessService", back_populates="organization", cascade="all, delete-orphan")
    suppliers = relationship("Supplier", back_populates="organization", cascade="all, delete-orphan")
    remediation_tasks = relationship("RemediationTask", back_populates="organization", cascade="all, delete-orphan")
    security_alerts = relationship("SecurityAlert", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="security_analyst") # super_admin, org_admin, security_analyst, security_engineer, read_only_exec
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="users")
