from typing import Dict, Any, List, Set, Optional
from sqlalchemy.orm import Session, selectinload
from app.models.asset import Application, BusinessService
from app.models.sbom import Component, DependencyRelationship, SBOMDocument
from app.models.vulnerability import Vulnerability, ComponentVulnerability

class BlastRadiusPropagationEngine:
    @staticmethod
    def analyze_propagation(
        db: Session,
        org_id: str,
        package_name: Optional[str] = None,
        package_version: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        component_id: Optional[str] = None
    ) -> Dict[str, Any]:
        target_components = []
        if component_id:
            c = (
                db.query(Component)
                .filter(Component.id == component_id)
                .options(selectinload(Component.sbom).selectinload(SBOMDocument.application))
                .first()
            )
            if c:
                target_components.append(c)
        elif package_name:
            query = db.query(Component).filter(Component.name.ilike(f"%{package_name}%"))
            if package_version:
                query = query.filter(Component.version == package_version)
            query = query.options(selectinload(Component.sbom).selectinload(SBOMDocument.application))
            target_components = query.all()
        elif vulnerability_id:
            cv_list = (
                db.query(ComponentVulnerability)
                .filter(ComponentVulnerability.vulnerability_id == vulnerability_id)
                .options(
                    selectinload(ComponentVulnerability.component)
                    .selectinload(Component.sbom)
                    .selectinload(SBOMDocument.application)
                )
                .all()
            )
            for cv in cv_list:
                if cv.component and cv.component not in target_components:
                    target_components.append(cv.component)

        if not target_components:
            return {
                "originating_component": f"{package_name or 'Unknown'}@{package_version or '0.0.0'}",
                "vulnerability_id": vulnerability_id or "N/A",
                "vulnerability_title": "No active vulnerable components matching query found in organization inventory",
                "severity": "LOW",
                "cvss_score": 0.0,
                "is_kev": False,
                "epss_score": 0.0,
                "blast_radius_score": 0.0,
                "affected_applications_count": 0,
                "affected_applications": [],
                "associated_business_services": [],
                "total_hourly_disruption_exposure": 0.0,
                "risk_factors": ["No components identified"],
                "confidence_level": "HIGH",
                "explainable_summary": "No applications within the organization's registered inventory are currently exposed.",
                "recommended_actions": ["Maintain continuous monitoring for newly ingested SBOMs."],
                "propagation_paths": []
            }

        vuln_record = None
        target_vid = vulnerability_id
        if not target_vid:
            first_cv = (
                db.query(ComponentVulnerability)
                .filter(ComponentVulnerability.component_id == target_components[0].id)
                .options(selectinload(ComponentVulnerability.vulnerability))
                .first()
            )
            if first_cv and first_cv.vulnerability:
                vuln_record = first_cv.vulnerability
                target_vid = vuln_record.id
        else:
            vuln_record = db.query(Vulnerability).filter(Vulnerability.id == target_vid).first()

        cvss = vuln_record.cvss_v3_score if vuln_record else 8.5
        sev = vuln_record.severity if vuln_record else "HIGH"
        is_kev = vuln_record.is_cisa_kev if vuln_record else False
        epss = vuln_record.epss_score if vuln_record else 0.12

        affected_apps_dict = {}
        associated_services_dict = {}
        propagation_paths = []

        for comp in target_components:
            sbom = comp.sbom
            if not sbom or not sbom.application:
                continue

            app = sbom.application
            app_full = (
                db.query(Application)
                .filter(Application.id == app.id)
                .options(selectinload(Application.business_services))
                .first()
            )

            path_trace = [app.name]
            if not comp.is_direct:
                path_trace.append("Transitive Dependency Layer")
            path_trace.append(f"{comp.name}@{comp.version}")

            if app.id not in affected_apps_dict:
                affected_apps_dict[app.id] = {
                    "id": app.id,
                    "name": app.name,
                    "environment": app.environment,
                    "business_criticality": app.business_criticality,
                    "internet_exposed": app.internet_exposed,
                    "dependency_depth": comp.depth,
                    "is_direct": comp.is_direct,
                    "path_trace": path_trace
                }

            propagation_paths.append({
                "application": app.name,
                "environment": app.environment,
                "is_direct": comp.is_direct,
                "depth": comp.depth,
                "path": path_trace
            })

            if app_full:
                for srv in app_full.business_services:
                    if srv.id not in associated_services_dict:
                        associated_services_dict[srv.id] = {
                            "id": srv.id,
                            "name": srv.name,
                            "criticality": srv.criticality,
                            "financial_impact_rating": srv.financial_impact_rating,
                            "owner_team": srv.owner_team
                        }

        vuln_base = (cvss / 10.0) * 35.0
        kev_boost = 20.0 if is_kev else 0.0
        app_exposure = min(len(affected_apps_dict) * 8.0, 20.0)
        internet_boost = 15.0 if any(a["internet_exposed"] for a in affected_apps_dict.values()) else 0.0
        service_boost = 10.0 if any(s["criticality"] in ("MISSION_CRITICAL", "BUSINESS_OPERATIONAL") for s in associated_services_dict.values()) else 0.0

        blast_radius = min(round(vuln_base + kev_boost + app_exposure + internet_boost + service_boost, 1), 100.0)
        total_financial_exposure = sum(s["financial_impact_rating"] for s in associated_services_dict.values())

        risk_factors = []
        if is_kev:
            risk_factors.append("VERIFIED ACTIVE EXPLOITATION: Present in CISA Known Exploited Vulnerabilities catalog.")
        if cvss >= 9.0:
            risk_factors.append(f"CRITICAL SEVERITY: CVSS v3 score of {cvss}/10 indicates potential remote code execution or complete compromise.")
        if any(a["internet_exposed"] for a in affected_apps_dict.values()):
            risk_factors.append("EXTERNAL ATTACK SURFACE: At least one affected application is directly accessible from the public Internet.")
        if len(affected_apps_dict) > 1:
            risk_factors.append(f"SHARED DEPENDENCY EXPOSURE: Cascades across {len(affected_apps_dict)} independent corporate applications.")
        if any(s["criticality"] == "MISSION_CRITICAL" for s in associated_services_dict.values()):
            risk_factors.append("CORE BUSINESS SERVICE RISK: Supports mission-critical services with substantial hourly financial downtime impact.")

        primary_pkg = f"{target_components[0].name}@{target_components[0].version}"
        summary = (
            f"POTENTIAL EXPOSURE ASSESSMENT: Software dependency '{primary_pkg}' contains vulnerability '{target_vid or 'UNSPECIFIED'}'. "
            f"Graph propagation reveals {len(affected_apps_dict)} downstream application(s) incorporate this component. "
            f"Importantly, this represents a structural dependency vulnerability and potential attack propagation route; "
            f"it does not constitute evidence of an active runtime compromise. "
            f"Calculated blast radius score is {blast_radius}/100 with estimated operational disruption exposure of ${total_financial_exposure:,.2f}/hr."
        )

        recommended_actions = [
            f"Prioritize remediation for Internet-exposed application(s): {', '.join(a['name'] for a in affected_apps_dict.values() if a['internet_exposed']) or 'None'}.",
            f"Upgrade '{target_components[0].name}' to the latest verified secure release across all repository build files.",
            "Deploy runtime WAF rules and compensating network ingress controls while package updates are undergoing staging validation.",
            "Rescan updated application SBOMs through Supply Chain Sentinel to verify eradication of the vulnerable dependency."
        ]

        return {
            "originating_component": primary_pkg,
            "vulnerability_id": target_vid or "UNKNOWN",
            "vulnerability_title": vuln_record.title if vuln_record else f"Vulnerability in {target_components[0].name}",
            "severity": sev,
            "cvss_score": cvss,
            "is_kev": is_kev,
            "epss_score": epss,
            "blast_radius_score": blast_radius,
            "affected_applications_count": len(affected_apps_dict),
            "affected_applications": list(affected_apps_dict.values()),
            "associated_business_services": list(associated_services_dict.values()),
            "total_hourly_disruption_exposure": total_financial_exposure,
            "risk_factors": risk_factors,
            "confidence_level": "HIGH" if (is_kev or cvss >= 9.0) else "MEDIUM",
            "explainable_summary": summary,
            "recommended_actions": recommended_actions,
            "propagation_paths": propagation_paths
        }
