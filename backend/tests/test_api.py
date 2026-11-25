import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.database import engine, Base, SessionLocal
from app.seed_data import seed_enterprise_demonstration

client = TestClient(app)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_enterprise_demonstration(db)
    yield

def test_health_check():
    """Verify system health, DB connection, and intelligence feed status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert "platform" in data

def test_authentication_flow():
    """Verify secure JWT generation and role validation."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "sarah.mitchell@sentinel-defense.internal", "password": "SentinelSecOps2026!"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["role"] == "security_analyst"

    # Test authenticated /me
    token = data["access_token"]
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "sarah.mitchell@sentinel-defense.internal"

def test_dashboard_overview():
    """Verify Module 1 Security Operations dashboard metrics."""
    response = client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert "metrics" in data
    assert data["metrics"]["total_assets"] >= 4
    assert data["metrics"]["total_vulnerabilities"] >= 4
    assert data["metrics"]["known_exploited_vulnerabilities"] >= 2
    assert "severity_distribution" in data
    assert "top_vulnerable_dependencies" in data

def test_asset_inventory():
    """Verify Module 2 Software Asset Discovery."""
    response = client.get("/api/v1/assets/applications")
    assert response.status_code == 200
    apps = response.json()
    assert len(apps) >= 4
    app_names = [a["name"] for a in apps]
    assert "Payment Gateway Service" in app_names
    assert "Order Fulfillment System" in app_names

def test_vulnerability_intelligence():
    """Verify Module 4 Vulnerability Threat Intelligence with EPSS and KEV."""
    response = client.get("/api/v1/vulnerabilities")
    assert response.status_code == 200
    vulns = response.json()
    assert len(vulns) >= 4
    
    cves = [v["id"] for v in vulns]
    assert "CVE-2021-44228" in cves # Log4Shell
    assert "CVE-2022-22965" in cves # Spring4Shell

    # Verify EPSS and KEV flags
    log4j = next(v for v in vulns if v["id"] == "CVE-2021-44228")
    assert log4j["is_cisa_kev"] is True
    assert log4j["cvss_v3_score"] == 10.0
    assert log4j["epss_score"] > 0.9

def test_dependency_graph():
    """Verify Module 5 Interactive Dependency Graph endpoint."""
    apps_resp = client.get("/api/v1/assets/applications")
    payment_app = next(a for a in apps_resp.json() if "Payment Gateway" in a["name"])
    
    response = client.get(f"/api/v1/graph/application/{payment_app['id']}")
    assert response.status_code == 200
    graph = response.json()
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0

def test_attack_propagation_and_blast_radius():
    """Verify Module 6 Attack Propagation and Blast Radius calculations."""
    payload = {"component_name": "log4j-core"}
    response = client.post("/api/v1/propagation/analyze", json=payload)
    assert response.status_code == 200
    res = response.json()
    
    assert res["originating_component"] == "log4j-core"
    assert res["blast_radius_score"] > 0
    assert res["affected_applications_count"] >= 2
    assert len(res["associated_business_services"]) >= 1
    assert res["total_hourly_disruption_exposure"] > 0
    assert "Payment Gateway Service" in [a["name"] for a in res["affected_applications"]]

def test_risk_prioritization_engine():
    """Verify Module 7 Multi-factor Risk Scoring Policy."""
    policy = {
        "cvss_weight": 0.30,
        "epss_weight": 0.20,
        "kev_weight": 0.25,
        "criticality_weight": 0.15,
        "exposure_weight": 0.10
    }
    response = client.post("/api/v1/risk/policy", json=policy)
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "success"
    assert "recalculated_applications" in res

def test_ai_security_analyst_rag():
    """Verify Module 8 Grounded AI Security Analyst RAG interaction."""
    chat_payload = {
        "query": "Which applications are vulnerable to Log4Shell (CVE-2021-44228) and what is the blast radius?",
        "conversation_id": "test-secops-session"
    }
    response = client.post("/api/v1/ai/chat", json=chat_payload)
    assert response.status_code == 200
    data = response.json()
    assert "response" in data
    assert "Payment Gateway" in data["response"] or "log4j" in data["response"].lower()
    assert len(data["grounding_references"]) > 0
    assert len(data["suggested_followups"]) > 0

def test_remediation_and_dual_sbom_verification():
    """Verify Module 9 Dual-SBOM mathematical rescan verification."""
    apps_resp = client.get("/api/v1/assets/applications")
    payment_app = next(a for a in apps_resp.json() if "Payment Gateway" in a["name"])
    
    payload = {
        "application_id": payment_app["id"],
        "new_sbom_id": "sbom-verification-simulated",
        "target_vulnerability_id": "CVE-2021-44228"
    }
    response = client.post("/api/v1/remediation/verify", json=payload)
    assert response.status_code == 200
    res = response.json()
    assert "verified" in res
    assert "previous_version" in res
    assert "current_version" in res

def test_third_party_supplier_risk():
    """Verify Module 10 Supplier Risk telemetry."""
    response = client.get("/api/v1/suppliers")
    assert response.status_code == 200
    suppliers = response.json()
    assert len(suppliers) >= 3
    names = [s["name"] for s in suppliers]
    assert "The Apache Software Foundation" in names

def test_continuous_alerts():
    """Verify Module 11 Real-time Security Alerts."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) >= 1

def test_executive_reports_and_csv_export():
    """Verify Module 12 Executive Briefing and CSV Vulnerability Register Export."""
    # Executive brief
    exec_resp = client.get("/api/v1/reports/executive")
    assert exec_resp.status_code == 200
    brief = exec_resp.json()
    assert "assessment_title" in brief
    assert "portfolio_posture" in brief

    # CSV Register Export
    csv_resp = client.get("/api/v1/reports/vulnerabilities/export/csv")
    assert csv_resp.status_code == 200
    csv_content = csv_resp.text
    assert "Vulnerability ID,Severity,CVSS v3,EPSS Score" in csv_content
    assert "CVE-2021-44228" in csv_content
