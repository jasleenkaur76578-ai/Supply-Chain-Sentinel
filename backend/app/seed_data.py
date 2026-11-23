import uuid
import datetime
from sqlalchemy.orm import Session
from app.models.organization import Organization, User
from app.models.asset import Application, BusinessService
from app.models.sbom import Supplier, SBOMDocument, Component, DependencyRelationship
from app.models.vulnerability import Vulnerability, ComponentVulnerability
from app.models.remediation import RemediationTask, SecurityAlert
from app.security.auth import get_password_hash
from app.config import settings

def stable_uuid(key: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"supply-chain-sentinel:{key}"))

def seed_enterprise_demonstration(db: Session):
    # Check if already seeded
    existing = db.query(Organization).filter(Organization.slug == "gflc").first()
    if existing:
        admin_email = settings.ADMIN_EMAIL.strip().lower()
        existing_admin = db.query(User).filter(User.email == admin_email).first()
        if not existing_admin:
            db.add(User(
                id=stable_uuid(f"user:{admin_email}"),
                org_id=existing.id,
                email=admin_email,
                hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                full_name=settings.ADMIN_FULL_NAME,
                role="super_admin",
                is_active=True
            ))
            db.commit()
        return

    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Create Organization
    org = Organization(
        id=stable_uuid("org:gflc"),
        name="Global Financial & Logistics Corp",
        slug="gflc",
        risk_policy={
            "weights": {
                "cvss_weight": 0.25,
                "epss_weight": 0.20,
                "kev_weight": 0.25,
                "criticality_weight": 0.15,
                "exposure_weight": 0.15
            }
        }
    )
    db.add(org)
    db.flush()

    # 2. Create Users across 5 Enterprise Roles
    admin_email = settings.ADMIN_EMAIL.strip().lower()
    users = [
        User(
            id=stable_uuid(f"user:{admin_email}"),
            org_id=org.id,
            email=admin_email,
            hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
            full_name=settings.ADMIN_FULL_NAME,
            role="super_admin"
        ),
        User(
            id=stable_uuid("user:ciso@sentinel.defense.org"),
            org_id=org.id,
            email="ciso@sentinel.defense.org",
            hashed_password=get_password_hash("SentinelCiso2026!"),
            full_name="Elena Rostova (CISO)",
            role="org_admin"
        ),
        User(
            id=stable_uuid("user:analyst@sentinel.defense.org"),
            org_id=org.id,
            email="analyst@sentinel.defense.org",
            hashed_password=get_password_hash("SentinelAnalyst2026!"),
            full_name="Dr. Sarah Mitchell",
            role="security_analyst"
        ),
        User(
            id=stable_uuid("user:engineer@sentinel.defense.org"),
            org_id=org.id,
            email="engineer@sentinel.defense.org",
            hashed_password=get_password_hash("SentinelEngineer2026!"),
            full_name="David Chen",
            role="security_engineer"
        ),
        User(
            id=stable_uuid("user:exec@sentinel.defense.org"),
            org_id=org.id,
            email="exec@sentinel.defense.org",
            hashed_password=get_password_hash("SentinelExec2026!"),
            full_name="Victoria Sterling (Audit Committee)",
            role="read_only_exec"
        )
    ]
    for u in users:
        db.add(u)
    db.flush()

    # 3. Create Business Services
    srv_trans = BusinessService(
        id=stable_uuid("svc:trans"),
        org_id=org.id,
        name="Core Cardholder Transaction Processing",
        criticality="MISSION_CRITICAL",
        financial_impact_rating=120000.0, # $120k/hr
        owner_team="FinTech Core Infrastructure"
    )
    srv_freight = BusinessService(
        id=stable_uuid("svc:freight"),
        org_id=org.id,
        name="Global Maritime Freight Routing",
        criticality="BUSINESS_OPERATIONAL",
        financial_impact_rating=45000.0,
        owner_team="Logistics Systems Operations"
    )
    srv_checkout = BusinessService(
        id=stable_uuid("svc:checkout"),
        org_id=org.id,
        name="Customer Digital Commerce Checkout",
        criticality="MISSION_CRITICAL",
        financial_impact_rating=85000.0,
        owner_team="E-Commerce Platform SecOps"
    )
    db.add_all([srv_trans, srv_freight, srv_checkout])
    db.flush()

    # 4. Create Applications
    app_payment = Application(
        id=stable_uuid("app:payment"),
        org_id=org.id,
        name="Enterprise Payment Gateway",
        repository_url="https://github.com/enterprise/payment-gateway-service",
        environment="PRODUCTION",
        business_criticality="CRITICAL",
        internet_exposed=True,
        current_risk_score=94.5
    )
    app_payment.business_services = [srv_trans, srv_checkout]

    app_order = Application(
        id=stable_uuid("app:order"),
        org_id=org.id,
        name="Order Fulfillment Engine",
        repository_url="https://github.com/enterprise/order-fulfillment-engine",
        environment="PRODUCTION",
        business_criticality="HIGH",
        internet_exposed=False,
        current_risk_score=72.0
    )
    app_order.business_services = [srv_checkout, srv_freight]

    app_portal = Application(
        id=stable_uuid("app:portal"),
        org_id=org.id,
        name="Customer Self-Service Portal",
        repository_url="https://github.com/enterprise/customer-web-portal",
        environment="PRODUCTION",
        business_criticality="HIGH",
        internet_exposed=True,
        current_risk_score=86.2
    )
    app_portal.business_services = [srv_checkout]

    app_telemetry = Application(
        id=stable_uuid("app:telemetry"),
        org_id=org.id,
        name="Logistics Telemetry Hub",
        repository_url="https://github.com/enterprise/logistics-telemetry-hub",
        environment="STAGING",
        business_criticality="MEDIUM",
        internet_exposed=False,
        current_risk_score=34.0
    )
    app_telemetry.business_services = [srv_freight]

    db.add_all([app_payment, app_order, app_portal, app_telemetry])
    db.flush()

    # 5. Create Suppliers
    sup_apache = Supplier(
        id=stable_uuid("sup:apache"),
        org_id=org.id,
        name="Apache Software Foundation",
        contact_email="security@apache.org",
        trust_tier="TIER_1_VERIFIED",
        security_assessment_score=92.0
    )
    sup_spring = Supplier(
        id=stable_uuid("sup:spring"),
        org_id=org.id,
        name="Spring.io / VMware Tanzu",
        contact_email="security@spring.io",
        trust_tier="TIER_1_VERIFIED",
        security_assessment_score=95.0
    )
    sup_fastcdn = Supplier(
        id=stable_uuid("sup:fastcdn"),
        org_id=org.id,
        name="FastEdge Micro-Vendor",
        contact_email="ops@fastedge.vendor.net",
        trust_tier="TIER_3_UNVERIFIED",
        security_assessment_score=58.0
    )
    db.add_all([sup_apache, sup_spring, sup_fastcdn])
    db.flush()

    # 6. Real Vulnerabilities
    v_log4j = Vulnerability(
        id="CVE-2021-44228",
        source="CISA_KEV",
        title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        summary="Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        details="An attacker who can provide log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
        cvss_v3_score=10.0,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity="CRITICAL",
        epss_score=0.9742,
        epss_percentile=0.9998,
        is_cisa_kev=True,
        cisa_kev_due_date=datetime.date(2021, 12, 24),
        published_at=datetime.datetime(2021, 12, 10, tzinfo=datetime.timezone.utc),
        last_modified_at=datetime.datetime(2024, 6, 12, tzinfo=datetime.timezone.utc)
    )

    v_spring4shell = Vulnerability(
        id="CVE-2022-22965",
        source="CISA_KEV",
        title="Spring Framework Remote Code Execution via DataBinder (Spring4Shell)",
        summary="A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding.",
        details="The specific exploit requires the application to run on Tomcat as a WAR deployment. If deployed as Spring Boot executable jar, default exploit does not work.",
        cvss_v3_score=9.8,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        epss_score=0.8920,
        epss_percentile=0.9945,
        is_cisa_kev=True,
        cisa_kev_due_date=datetime.date(2022, 4, 25),
        published_at=datetime.datetime(2022, 4, 1, tzinfo=datetime.timezone.utc),
        last_modified_at=datetime.datetime(2024, 3, 15, tzinfo=datetime.timezone.utc)
    )

    v_lodash = Vulnerability(
        id="CVE-2019-10744",
        source="NVD",
        title="Lodash Prototype Pollution Vulnerability",
        summary="Versions of lodash prior to 4.17.12 are vulnerable to Prototype Pollution in the defaultsDeep function.",
        details="The function defaultsDeep could be tricked into adding or modifying properties of Object.prototype using a constructor payload.",
        cvss_v3_score=7.3,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        severity="HIGH",
        epss_score=0.2310,
        epss_percentile=0.9412,
        is_cisa_kev=False,
        published_at=datetime.datetime(2019, 7, 2, tzinfo=datetime.timezone.utc),
        last_modified_at=datetime.datetime(2023, 11, 1, tzinfo=datetime.timezone.utc)
    )

    v_rapidreset = Vulnerability(
        id="CVE-2023-44487",
        source="CISA_KEV",
        title="HTTP/2 Rapid Reset Distributed Denial of Service",
        summary="The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly.",
        details="An attacker can initiate streams and immediately cancel them with RST_STREAM frames, bypassing standard concurrency limits.",
        cvss_v3_score=7.5,
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        severity="HIGH",
        epss_score=0.6540,
        epss_percentile=0.9820,
        is_cisa_kev=True,
        published_at=datetime.datetime(2023, 10, 10, tzinfo=datetime.timezone.utc),
        last_modified_at=datetime.datetime(2024, 2, 20, tzinfo=datetime.timezone.utc)
    )

    db.add_all([v_log4j, v_spring4shell, v_lodash, v_rapidreset])
    db.flush()

    # 7. Create SBOM Documents and Components for Payment Gateway
    sbom_pay = SBOMDocument(
        id=stable_uuid("sbom:payment"),
        application_id=app_payment.id,
        format="CYCLONEDX_JSON",
        spec_version="1.4",
        file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_name="payment-gateway-sbom.json",
        component_count=6,
        dependency_count=5,
        is_latest=True
    )
    db.add(sbom_pay)
    db.flush()
    app_payment.active_sbom_id = sbom_pay.id

    c_spring_boot = Component(
        id=stable_uuid("comp:payment:spring-starter"),
        sbom_id=sbom_pay.id,
        supplier_id=sup_spring.id,
        purl="pkg:maven/org.springframework.boot/spring-boot-starter-web@2.5.4",
        name="spring-boot-starter-web",
        version="2.5.4",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=True,
        depth=1
    )
    c_spring_logging = Component(
        id=stable_uuid("comp:payment:log4j-api"),
        sbom_id=sbom_pay.id,
        supplier_id=sup_spring.id,
        purl="pkg:maven/org.springframework.boot/spring-boot-starter-logging@2.5.4",
        name="spring-boot-starter-logging",
        version="2.5.4",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=False,
        depth=2
    )
    c_log4j_pay = Component(
        id=stable_uuid("comp:payment:log4j-core"),
        sbom_id=sbom_pay.id,
        supplier_id=sup_apache.id,
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        name="log4j-core",
        version="2.14.1",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=False,
        depth=3
    )
    c_jackson = Component(
        id=stable_uuid("comp:payment:jackson"),
        sbom_id=sbom_pay.id,
        supplier_id=sup_apache.id,
        purl="pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.4",
        name="jackson-databind",
        version="2.12.4",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=True,
        depth=1
    )
    db.add_all([c_spring_boot, c_spring_logging, c_log4j_pay, c_jackson])
    db.flush()

    # Link relationships in Payment Gateway
    rel_1 = DependencyRelationship(sbom_id=sbom_pay.id, parent_component_id=c_spring_boot.id, child_component_id=c_spring_logging.id, relationship_type="DEPENDS_ON")
    rel_2 = DependencyRelationship(sbom_id=sbom_pay.id, parent_component_id=c_spring_logging.id, child_component_id=c_log4j_pay.id, relationship_type="DEPENDS_ON")
    db.add_all([rel_1, rel_2])

    cv_1 = ComponentVulnerability(
        component_id=c_log4j_pay.id,
        vulnerability_id=v_log4j.id,
        verification_status="POTENTIAL_EXPOSURE",
        remediation_available=True,
        fixed_version="2.17.1"
    )
    db.add(cv_1)

    # 8. Create SBOM for Order Fulfillment (shares log4j-core directly!)
    sbom_order = SBOMDocument(
        id=stable_uuid("sbom:order"),
        application_id=app_order.id,
        format="CYCLONEDX_JSON",
        spec_version="1.4",
        file_hash_sha256="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        file_name="order-fulfillment-sbom.json",
        component_count=4,
        dependency_count=3,
        is_latest=True
    )
    db.add(sbom_order)
    db.flush()
    app_order.active_sbom_id = sbom_order.id

    c_log4j_order = Component(
        id=stable_uuid("comp:order:log4j-core"),
        sbom_id=sbom_order.id,
        supplier_id=sup_apache.id,
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        name="log4j-core",
        version="2.14.1",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=True,
        depth=1
    )
    c_okhttp = Component(
        id=stable_uuid("comp:order:okhttp"),
        sbom_id=sbom_order.id,
        supplier_id=sup_apache.id,
        purl="pkg:maven/com.squareup.okhttp3/okhttp@4.9.1",
        name="okhttp",
        version="4.9.1",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=True,
        depth=1
    )
    db.add_all([c_log4j_order, c_okhttp])
    db.flush()

    cv_2 = ComponentVulnerability(
        component_id=c_log4j_order.id,
        vulnerability_id=v_log4j.id,
        verification_status="POTENTIAL_EXPOSURE",
        remediation_available=True,
        fixed_version="2.17.1"
    )
    db.add(cv_2)

    # 9. Create SBOM for Customer Portal (Spring4Shell & Lodash)
    sbom_portal = SBOMDocument(
        id=stable_uuid("sbom:portal"),
        application_id=app_portal.id,
        format="SPDX_JSON",
        spec_version="2.3",
        file_hash_sha256="c7f1d2e3b4a56987123456789abcdef0123456789abcdef0123456789abcdef0",
        file_name="customer-portal-spdx.json",
        component_count=5,
        dependency_count=4,
        is_latest=True
    )
    db.add(sbom_portal)
    db.flush()
    app_portal.active_sbom_id = sbom_portal.id

    c_spring_beans = Component(
        id=stable_uuid("comp:portal:spring-beans"),
        sbom_id=sbom_portal.id,
        supplier_id=sup_spring.id,
        purl="pkg:maven/org.springframework/spring-beans@5.3.17",
        name="spring-beans",
        version="5.3.17",
        ecosystem="Maven",
        license_declared="Apache-2.0",
        is_direct=True,
        depth=1
    )
    c_lodash_portal = Component(
        id=stable_uuid("comp:portal:lodash"),
        sbom_id=sbom_portal.id,
        supplier_id=sup_fastcdn.id,
        purl="pkg:npm/lodash@4.17.11",
        name="lodash",
        version="4.17.11",
        ecosystem="npm",
        license_declared="MIT",
        is_direct=True,
        depth=1
    )
    db.add_all([c_spring_beans, c_lodash_portal])
    db.flush()

    cv_3 = ComponentVulnerability(
        component_id=c_spring_beans.id,
        vulnerability_id=v_spring4shell.id,
        verification_status="POTENTIAL_EXPOSURE",
        remediation_available=True,
        fixed_version="5.3.18"
    )
    cv_4 = ComponentVulnerability(
        component_id=c_lodash_portal.id,
        vulnerability_id=v_lodash.id,
        verification_status="POTENTIAL_EXPOSURE",
        remediation_available=True,
        fixed_version="4.17.21"
    )
    db.add_all([cv_3, cv_4])

    # 10. Remediation Tasks
    task_1 = RemediationTask(
        id=stable_uuid("task:log4j-payment"),
        org_id=org.id,
        application_id=app_payment.id,
        component_id=c_log4j_pay.id,
        vulnerability_id=v_log4j.id,
        title="Remediate Log4Shell (CVE-2021-44228) in Payment Gateway",
        description="Upgrade org.apache.logging.log4j:log4j-core from 2.14.1 to 2.17.1 across POM dependencies. Temporary JVM flag -Dlog4j2.formatMsgNoLookups=true applied to containers.",
        priority="URGENT",
        status="IN_PROGRESS",
        assigned_team="Core FinTech SecOps",
        target_resolution_date=datetime.date.today() + datetime.timedelta(days=2),
        recommended_version="2.17.1",
        compensating_controls="JVM argument -Dlog4j2.formatMsgNoLookups=true set; AWS WAF Log4j inspection rule enabled on ingress."
    )
    task_2 = RemediationTask(
        id=stable_uuid("task:spring4shell-portal"),
        org_id=org.id,
        application_id=app_portal.id,
        component_id=c_spring_beans.id,
        vulnerability_id=v_spring4shell.id,
        title="Patch Spring4Shell (CVE-2022-22965) in Customer Web Portal",
        description="Upgrade spring-beans to 5.3.18 or higher to mitigate class loader manipulation via DataBinder.",
        priority="URGENT",
        status="OPEN",
        assigned_team="Digital Portal Engineering",
        target_resolution_date=datetime.date.today() + datetime.timedelta(days=3),
        recommended_version="5.3.18",
        compensating_controls="App runs as standalone Spring Boot jar (mitigates default Tomcat exploit vector)."
    )
    db.add_all([task_1, task_2])

    # 11. Security Alerts
    alert_1 = SecurityAlert(
        id=stable_uuid("alert:kev-gateway"),
        org_id=org.id,
        title="CRITICAL ALERT: CISA KEV Exploited Component in Production Gateway",
        message="Active CISA KEV entry CVE-2021-44228 identified in transitive dependency log4j-core@2.14.1 affecting Internet-exposed Enterprise Payment Gateway.",
        severity="CRITICAL",
        entity_type="VULNERABILITY",
        entity_id=v_log4j.id
    )
    alert_2 = SecurityAlert(
        id=stable_uuid("alert:shared-blast"),
        org_id=org.id,
        title="Shared Dependency Blast Radius Warning",
        message="Package log4j-core@2.14.1 is shared between Enterprise Payment Gateway and Order Fulfillment Engine, creating unified downstream exposure.",
        severity="HIGH",
        entity_type="VULNERABILITY",
        entity_id=v_log4j.id
    )
    db.add_all([alert_1, alert_2])

    db.commit()
