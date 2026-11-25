from typing import Dict, Any
from sqlalchemy.orm import Session, selectinload
from app.models.asset import Application
from app.models.sbom import Component
from app.models.vulnerability import ComponentVulnerability

class EnterpriseRiskEngine:
    DEFAULT_POLICY = {
        "cvss_weight": 0.25,
        "epss_weight": 0.20,
        "kev_weight": 0.25,
        "criticality_weight": 0.15,
        "exposure_weight": 0.15
    }

    @classmethod
    def evaluate_application_risk(
        cls,
        db: Session,
        application_id: str,
        custom_weights: Dict[str, float] = None
    ) -> Dict[str, Any]:
        weights = custom_weights or cls.DEFAULT_POLICY

        app = (
            db.query(Application)
            .filter(Application.id == application_id)
            .options(
                selectinload(Application.business_services),
                selectinload(Application.sboms)
            )
            .first()
        )
        if not app:
            return {}

        latest_sbom = next((s for s in app.sboms if s.is_latest), None) if app.sboms else None
        if not latest_sbom and app.sboms:
            latest_sbom = app.sboms[-1]

        components = []
        if latest_sbom:
            components = (
                db.query(Component)
                .filter(Component.sbom_id == latest_sbom.id)
                .options(
                    selectinload(Component.vulnerabilities).selectinload(ComponentVulnerability.vulnerability)
                )
                .all()
            )

        max_cvss = 0.0
        max_epss = 0.0
        has_kev = False
        critical_count = 0
        high_count = 0
        direct_vuln_count = 0

        for comp in components:
            for cv in comp.vulnerabilities:
                if cv.vulnerability:
                    v = cv.vulnerability
                    max_cvss = max(max_cvss, v.cvss_v3_score)
                    max_epss = max(max_epss, v.epss_score)
                    if v.is_cisa_kev:
                        has_kev = True
                    sev = v.severity.upper()
                    if sev == "CRITICAL" or v.cvss_v3_score >= 9.0:
                        critical_count += 1
                    elif sev == "HIGH" or v.cvss_v3_score >= 7.0:
                        high_count += 1

                    if comp.is_direct:
                        direct_vuln_count += 1

        cvss_component = (max_cvss / 10.0) * 100.0 * weights.get("cvss_weight", 0.25)
        epss_component = (max_epss * 100.0) * weights.get("epss_weight", 0.20)
        kev_component = (100.0 if has_kev else 0.0) * weights.get("kev_weight", 0.25)

        crit_scale = {"CRITICAL": 100.0, "MISSION_CRITICAL": 100.0, "HIGH": 75.0, "MEDIUM": 50.0, "LOW": 25.0}
        app_crit_val = crit_scale.get(app.business_criticality.upper(), 50.0)
        criticality_component = app_crit_val * weights.get("criticality_weight", 0.15)
        exp_val = 100.0 if app.internet_exposed else 30.0
        exposure_component = exp_val * weights.get("exposure_weight", 0.15)

        depth_attenuation = 1.10 if direct_vuln_count > 0 else 0.95
        raw_total = (cvss_component + epss_component + kev_component + criticality_component + exposure_component) * depth_attenuation
        total_score = min(max(round(raw_total, 1), 0.0), 100.0)

        if total_score >= 80.0:
            tier = "CRITICAL"
        elif total_score >= 60.0:
            tier = "HIGH"
        elif total_score >= 35.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        drivers = []
        if has_kev:
            drivers.append("Component has a verified active exploit documented in CISA KEV catalog.")
        if max_cvss >= 9.0:
            drivers.append(f"Contains critical vulnerability with CVSS score {max_cvss}/10.")
        if app.internet_exposed:
            drivers.append("Application is publicly accessible from the Internet, expanding attack surface.")
        if app.business_criticality in ("CRITICAL", "HIGH"):
            drivers.append(f"Application is classified as '{app.business_criticality}' tier within the organization.")
        if direct_vuln_count > 0:
            drivers.append(f"Identified {direct_vuln_count} direct dependency vulnerability requiring priority patch.")
        if not drivers:
            drivers.append("Low overall exposure; standard patch cadence recommended.")

        app.current_risk_score = total_score
        db.commit()

        return {
            "application_id": app.id,
            "application_name": app.name,
            "environment": app.environment,
            "business_criticality": app.business_criticality,
            "internet_exposed": app.internet_exposed,
            "overall_score": total_score,
            "risk_tier": tier,
            "breakdown": {
                "cvss_component": round(cvss_component, 2),
                "epss_component": round(epss_component, 2),
                "kev_component": round(kev_component, 2),
                "criticality_component": round(criticality_component, 2),
                "exposure_component": round(exposure_component, 2),
                "depth_attenuation": depth_attenuation,
                "total_score": total_score
            },
            "primary_risk_drivers": drivers,
            "critical_vulnerabilities_count": critical_count,
            "high_vulnerabilities_count": high_count
        }
