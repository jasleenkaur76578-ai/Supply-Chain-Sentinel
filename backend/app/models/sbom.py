import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from app.database import Base

def gen_uuid():
    return str(uuid.uuid4())

def utc_now():
    return datetime.now(timezone.utc)

class Supplier(Base):
    __tablename__ = "suppliers"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    org_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    contact_email = Column(String(255), default="")
    trust_tier = Column(String(50), default="TIER_2_STANDARD") # TIER_1_VERIFIED, TIER_2_STANDARD, TIER_3_UNVERIFIED, HIGH_RISK
    security_assessment_score = Column(Float, default=75.0)
    review_status = Column(String(50), default="ACTIVE_MONITORING")
    created_at = Column(DateTime, default=utc_now)

    organization = relationship("Organization", back_populates="suppliers")
    components = relationship("Component", back_populates="supplier")

class SBOMDocument(Base):
    __tablename__ = "sbom_documents"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    application_id = Column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    format = Column(String(50), nullable=False) # CYCLONEDX_JSON, CYCLONEDX_XML, SPDX_JSON
    spec_version = Column(String(50), default="1.4")
    serial_number = Column(String(255), default="")
    version = Column(Integer, default=1)
    file_hash_sha256 = Column(String(64), nullable=False)
    file_name = Column(String(255), default="sbom.json")
    component_count = Column(Integer, default=0)
    dependency_count = Column(Integer, default=0)
    is_latest = Column(Boolean, default=True)
    raw_content = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now)

    application = relationship("Application", back_populates="sboms")
    components = relationship("Component", back_populates="sbom", cascade="all, delete-orphan")
    dependency_relationships = relationship("DependencyRelationship", back_populates="sbom", cascade="all, delete-orphan")

class Component(Base):
    __tablename__ = "components"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    sbom_id = Column(String(36), ForeignKey("sbom_documents.id", ondelete="CASCADE"), nullable=False)
    supplier_id = Column(String(36), ForeignKey("suppliers.id", ondelete="SET NULL"), nullable=True)
    purl = Column(String(1024), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(100), nullable=False)
    ecosystem = Column(String(100), nullable=False, default="npm") # maven, npm, pypi, golang, etc.
    license_declared = Column(String(255), default="NOASSERTION")
    is_direct = Column(Boolean, default=True)
    depth = Column(Integer, default=1)
    created_at = Column(DateTime, default=utc_now)

    sbom = relationship("SBOMDocument", back_populates="components")
    supplier = relationship("Supplier", back_populates="components")
    vulnerabilities = relationship("ComponentVulnerability", back_populates="component", cascade="all, delete-orphan")
    upstream_relations = relationship("DependencyRelationship", foreign_keys="DependencyRelationship.child_component_id", back_populates="child_component")
    downstream_relations = relationship("DependencyRelationship", foreign_keys="DependencyRelationship.parent_component_id", back_populates="parent_component")

class DependencyRelationship(Base):
    __tablename__ = "dependency_relationships"

    id = Column(String(36), primary_key=True, default=gen_uuid)
    sbom_id = Column(String(36), ForeignKey("sbom_documents.id", ondelete="CASCADE"), nullable=False)
    parent_component_id = Column(String(36), ForeignKey("components.id", ondelete="CASCADE"), nullable=False, index=True)
    child_component_id = Column(String(36), ForeignKey("components.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), default="DEPENDS_ON") # DEPENDS_ON, CONTAINS, OPTIONAL

    sbom = relationship("SBOMDocument", back_populates="dependency_relationships")
    parent_component = relationship("Component", foreign_keys=[parent_component_id], back_populates="downstream_relations")
    child_component = relationship("Component", foreign_keys=[child_component_id], back_populates="upstream_relations")
