from typing import Dict, Any, List
from sqlalchemy.orm import Session, selectinload
from app.models.asset import Application
from app.models.sbom import SBOMDocument, Component, DependencyRelationship
from app.models.vulnerability import ComponentVulnerability, Vulnerability

class DependencyGraphEngine:
    @staticmethod
    def build_application_graph(
        db: Session,
        application_id: str,
        max_depth: int = 5,
        include_vulnerabilities: bool = True
    ) -> Dict[str, Any]:
        application = (
            db.query(Application)
            .filter(Application.id == application_id)
            .options(selectinload(Application.business_services))
            .first()
        )
        if not application:
            return {"nodes": [], "edges": []}

        sbom = (
            db.query(SBOMDocument)
            .filter(SBOMDocument.application_id == application_id)
            .order_by(SBOMDocument.created_at.desc())
            .first()
        )
        if not sbom:
            return {
                "nodes": [{
                    "id": f"app-{application.id}",
                    "type": "applicationNode",
                    "data": {
                        "label": application.name,
                        "environment": application.environment,
                        "criticality": application.business_criticality,
                        "risk_score": application.current_risk_score,
                        "internet_exposed": application.internet_exposed
                    },
                    "position": {"x": 250, "y": 50}
                }],
                "edges": []
            }

        components = (
            db.query(Component)
            .filter(Component.sbom_id == sbom.id)
            .options(selectinload(Component.vulnerabilities).selectinload(ComponentVulnerability.vulnerability))
            .all()
        )

        relationships = (
            db.query(DependencyRelationship)
            .filter(DependencyRelationship.sbom_id == sbom.id)
            .all()
        )

        nodes = []
        edges = []

        # Application Root Node
        app_node_id = f"app-{application.id}"
        nodes.append({
            "id": app_node_id,
            "type": "applicationNode",
            "data": {
                "label": application.name,
                "environment": application.environment,
                "criticality": application.business_criticality,
                "risk_score": application.current_risk_score,
                "internet_exposed": application.internet_exposed,
                "entity_type": "APPLICATION"
            },
            "position": {"x": 400, "y": 40}
        })

        # Business Services
        for idx, srv in enumerate(application.business_services):
            srv_node_id = f"srv-{srv.id}"
            nodes.append({
                "id": srv_node_id,
                "type": "serviceNode",
                "data": {
                    "label": srv.name,
                    "criticality": srv.criticality,
                    "financial_impact": srv.financial_impact_rating,
                    "owner_team": srv.owner_team,
                    "entity_type": "BUSINESS_SERVICE"
                },
                "position": {"x": 100 + (idx * 300), "y": -120}
            })
            edges.append({
                "id": f"e-{srv_node_id}-{app_node_id}",
                "source": srv_node_id,
                "target": app_node_id,
                "label": "supports",
                "animated": True,
                "style": {"stroke": "#6366F1", "strokeWidth": 2}
            })

        # Components
        direct_comps = [c for c in components if c.is_direct]
        transitive_comps = [c for c in components if not c.is_direct]
        x_spacing = 220
        y_step = 160

        for idx, comp in enumerate(direct_comps):
            comp_node_id = f"comp-{comp.id}"
            highest_sev = "LOW"
            highest_cvss = 0.0
            vuln_count = len(comp.vulnerabilities)

            for cv in comp.vulnerabilities:
                if cv.vulnerability:
                    v_sev = cv.vulnerability.severity.upper()
                    if v_sev == "CRITICAL" or cv.vulnerability.cvss_v3_score >= 9.0:
                        highest_sev = "CRITICAL"
                        highest_cvss = max(highest_cvss, cv.vulnerability.cvss_v3_score)
                    elif v_sev == "HIGH" and highest_sev != "CRITICAL":
                        highest_sev = "HIGH"
                        highest_cvss = max(highest_cvss, cv.vulnerability.cvss_v3_score)
                    elif v_sev == "MEDIUM" and highest_sev not in ("CRITICAL", "HIGH"):
                        highest_sev = "MEDIUM"

            nodes.append({
                "id": comp_node_id,
                "type": "componentNode",
                "data": {
                    "label": f"{comp.name}@{comp.version}",
                    "name": comp.name,
                    "version": comp.version,
                    "ecosystem": comp.ecosystem,
                    "is_direct": True,
                    "depth": 1,
                    "vuln_count": vuln_count,
                    "severity": highest_sev if vuln_count > 0 else "NONE",
                    "highest_cvss": highest_cvss,
                    "entity_type": "COMPONENT"
                },
                "position": {"x": 80 + (idx * x_spacing), "y": 40 + y_step}
            })

            edges.append({
                "id": f"e-{app_node_id}-{comp_node_id}",
                "source": app_node_id,
                "target": comp_node_id,
                "label": "direct_dep",
                "style": {"stroke": "#38BDF8", "strokeWidth": 1.5}
            })

        for idx, comp in enumerate(transitive_comps):
            if comp.depth > max_depth:
                continue
            comp_node_id = f"comp-{comp.id}"
            highest_sev = "LOW"
            highest_cvss = 0.0
            vuln_count = len(comp.vulnerabilities)

            for cv in comp.vulnerabilities:
                if cv.vulnerability:
                    v_sev = cv.vulnerability.severity.upper()
                    if v_sev == "CRITICAL" or cv.vulnerability.cvss_v3_score >= 9.0:
                        highest_sev = "CRITICAL"
                        highest_cvss = max(highest_cvss, cv.vulnerability.cvss_v3_score)
                    elif v_sev == "HIGH" and highest_sev != "CRITICAL":
                        highest_sev = "HIGH"
                        highest_cvss = max(highest_cvss, cv.vulnerability.cvss_v3_score)
                    elif v_sev == "MEDIUM" and highest_sev not in ("CRITICAL", "HIGH"):
                        highest_sev = "MEDIUM"

            nodes.append({
                "id": comp_node_id,
                "type": "componentNode",
                "data": {
                    "label": f"{comp.name}@{comp.version}",
                    "name": comp.name,
                    "version": comp.version,
                    "ecosystem": comp.ecosystem,
                    "is_direct": False,
                    "depth": comp.depth,
                    "vuln_count": vuln_count,
                    "severity": highest_sev if vuln_count > 0 else "NONE",
                    "highest_cvss": highest_cvss,
                    "entity_type": "COMPONENT"
                },
                "position": {"x": 80 + (idx * x_spacing), "y": 40 + (y_step * 2)}
            })

        for rel in relationships:
            parent_id = f"comp-{rel.parent_component_id}"
            child_id = f"comp-{rel.child_component_id}"
            if any(n["id"] == parent_id for n in nodes) and any(n["id"] == child_id for n in nodes):
                edges.append({
                    "id": f"e-{parent_id}-{child_id}",
                    "source": parent_id,
                    "target": child_id,
                    "label": "transitive_dep",
                    "style": {"stroke": "#94A3B8", "strokeDasharray": "4 4", "strokeWidth": 1.2}
                })

        if include_vulnerabilities:
            for comp in components:
                for cv in comp.vulnerabilities:
                    if cv.vulnerability:
                        v = cv.vulnerability
                        v_node_id = f"vuln-{v.id}-{comp.id}"
                        color = "#EF4444" if v.severity == "CRITICAL" or v.is_cisa_kev else ("#F97316" if v.severity == "HIGH" else "#EAB308")
                        nodes.append({
                            "id": v_node_id,
                            "type": "vulnerabilityNode",
                            "data": {
                                "label": v.id,
                                "title": v.title,
                                "cvss": v.cvss_v3_score,
                                "severity": v.severity,
                                "is_kev": v.is_cisa_kev,
                                "epss": v.epss_score,
                                "entity_type": "VULNERABILITY"
                            },
                            "position": {"x": 80 + (components.index(comp) * x_spacing), "y": 40 + (y_step * 3)}
                        })
                        edges.append({
                            "id": f"e-comp-{comp.id}-{v_node_id}",
                            "source": f"comp-{comp.id}",
                            "target": v_node_id,
                            "label": "affected_by",
                            "animated": True,
                            "style": {"stroke": color, "strokeWidth": 2}
                        })

        return {"nodes": nodes, "edges": edges}
