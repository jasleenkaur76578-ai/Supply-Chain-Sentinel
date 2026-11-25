import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import engine, Base, SessionLocal
from app.seed_data import seed_enterprise_demonstration
from app.models.organization import Organization, User
from app.models.asset import Application
from app.models.vulnerability import Vulnerability
from app.services.blast_radius import BlastRadiusPropagationEngine
from app.services.risk_engine import EnterpriseRiskEngine
from app.services.graph_engine import DependencyGraphEngine
from app.services.ai_assistant import AISecurityAnalyst
from app.services.remediation_service import RemediationService
from app.services.reporting_service import ExecutiveReportingService
from app.security.auth import get_password_hash, verify_password, create_access_token, decode_access_token

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_enterprise_demonstration(db)
    yield

def test_database_seeding_and_integrity():
    """Verify core enterprise inventory has been seeded accurately."""
    with SessionLocal() as db:
        apps = db.query(Application).all()
        vulns = db.query(Vulnerability).all()
        users = db.query(User).all()

        assert len(apps) >= 4
        assert len(vulns) >= 4
        assert len(users) >= 5

        # Verify Log4j is present with Critical CVSS 10.0 and KEV
        log4j = db.query(Vulnerability).filter(Vulnerability.id == "CVE-2021-44228").first()
        assert log4j is not None
        assert log4j.cvss_v3_score == 10.0
        assert log4j.is_cisa_kev is True
        assert log4j.epss_score > 0.9

def test_auth_and_rbac_crypto():
    """Verify bcrypt password hashing and JWT token creation/decoding."""
    password = "SentinelTestPassword2026!"
    hashed = get_password_hash(password)
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

    # JWT generation
    token = create_access_token(
        data={"sub": "analyst@sentinel.defense.org", "role": "security_analyst", "org_id": "test-org"}
    )
    assert token is not None
    payload = decode_access_token(token)
    assert payload["sub"] == "analyst@sentinel.defense.org"
    assert payload["role"] == "security_analyst"

def test_blast_radius_engine_calculation():
    """Verify Module 6 Attack Propagation and Blast Radius calculations."""
    with SessionLocal() as db:
        org = db.query(Organization).first()
        assert org is not None

        result = BlastRadiusPropagationEngine.analyze_propagation(db, org_id=org.id, package_name="log4j-core")
        
        assert "log4j-core" in result["originating_component"]
        assert result["blast_radius_score"] > 50  # High exposure due to Log4j in payment gateway
        assert result["affected_applications_count"] >= 2
        assert len(result["associated_business_services"]) >= 1
        assert result["total_hourly_disruption_exposure"] > 0
        assert len(result["risk_factors"]) > 0

        # Verify affected applications contain Payment Gateway
        app_names = [a["name"] for a in result["affected_applications"]]
        assert any("Payment Gateway" in name for name in app_names)

def test_dependency_graph_engine():
    """Verify Module 5 Interactive Graph node and edge generation."""
    with SessionLocal() as db:
        payment_app = db.query(Application).filter(Application.name.like("%Payment Gateway%")).first()
        assert payment_app is not None

        graph = DependencyGraphEngine.build_application_graph(db, application_id=payment_app.id, max_depth=5)
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) >= 3
        assert len(graph["edges"]) >= 2

        # Verify node structure conforms to React Flow
        first_node = graph["nodes"][0]
        assert "id" in first_node
        assert "data" in first_node
        assert "position" in first_node

def test_risk_scoring_engine():
    """Verify Module 7 Multi-factor transparent risk scoring."""
    with SessionLocal() as db:
        payment_app = db.query(Application).filter(Application.name.like("%Payment Gateway%")).first()
        assert payment_app is not None

        custom_weights = {
            "cvss_weight": 0.30,
            "epss_weight": 0.20,
            "kev_weight": 0.25,
            "criticality_weight": 0.15,
            "exposure_weight": 0.10
        }
        assessment = EnterpriseRiskEngine.evaluate_application_risk(db, payment_app.id, custom_weights=custom_weights)
        assert assessment["application_id"] == payment_app.id
        assert 0 <= assessment["overall_score"] <= 100
        assert "breakdown" in assessment
        assert len(assessment["primary_risk_drivers"]) > 0

def test_ai_security_analyst_grounded_rag():
    """Verify Module 8 Grounded RAG AI Security Analyst retrieval."""
    with SessionLocal() as db:
        query = "What is our exposure to Log4j (CVE-2021-44228) and which applications are affected?"
        result = AISecurityAnalyst.chat(db, query=query, conversation_id="test-conv")
        
        assert "response" in result
        assert len(result["grounding_references"]) > 0
        assert len(result["suggested_followups"]) > 0
        # Response should identify Payment Gateway or Log4j
        assert "Payment Gateway" in result["response"] or "log4j" in result["response"].lower()

def test_remediation_dual_sbom_verification():
    """Verify Module 9 Mathematical Dual-SBOM rescan verification."""
    with SessionLocal() as db:
        payment_app = db.query(Application).filter(Application.name.like("%Payment Gateway%")).first()
        assert payment_app is not None

        result = RemediationService.verify_remediation(
            db=db,
            application_id=payment_app.id,
            new_sbom_id="simulated-rescan-sbom",
            target_vulnerability_id="CVE-2021-44228"
        )
        assert "verified" in result
        assert "previous_version" in result
        assert "current_version" in result
        assert "residual_risk" in result

def test_reporting_service_and_csv():
    """Verify Module 12 Executive Briefing and CSV Vulnerability Register Export."""
    with SessionLocal() as db:
        org = db.query(Organization).first()
        assert org is not None

        exec_report = ExecutiveReportingService.generate_executive_report(db, org_id=org.id)
        assert "metadata" in exec_report
        assert "executive_summary" in exec_report

        csv_text = ExecutiveReportingService.export_vulnerabilities_csv(db)
        assert "Vulnerability ID,Title,Severity,CVSS v3.1 Score" in csv_text
        assert "CVE-2021-44228" in csv_text
