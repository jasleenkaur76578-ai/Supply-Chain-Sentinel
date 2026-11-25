import csv
import io
from typing import Dict, Any, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session, selectinload
from app.models.asset import Application
from app.models.vulnerability import Vulnerability
from app.models.remediation import RemediationTask

class ExecutiveReportingService:
    @staticmethod
    def generate_executive_report(db: Session, org_id: str) -> Dict[str, Any]:
        apps = (
            db.query(Application)
            .filter(Application.org_id == org_id)
            .options(selectinload(Application.business_services))
            .all()
        )
        vulns = db.query(Vulnerability).order_by(Vulnerability.cvss_v3_score.desc()).all()
        tasks = db.query(RemediationTask).filter(RemediationTask.org_id == org_id).all()

        crit_count = sum(1 for v in vulns if v.severity == "CRITICAL" or v.cvss_v3_score >= 9.0)
        high_count = sum(1 for v in vulns if v.severity == "HIGH")
        kev_count = sum(1 for v in vulns if v.is_cisa_kev)
        resolved_count = sum(1 for t in tasks if t.status == "RESOLVED")
        completion_rate = (resolved_count / len(tasks) * 100.0) if tasks else 100.0

        return {
            "metadata": {
                "report_title": "Enterprise Software Supply Chain Risk Intelligence & Blast Radius Report",
                "organization_id": org_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "classification": "CONFIDENTIAL / CYBERSECURITY EXECUTIVE ASSESSMENT",
                "version": "1.0.0"
            },
            "executive_summary": {
                "total_monitored_applications": len(apps),
                "total_vulnerabilities": len(vulns),
                "critical_vulnerabilities": crit_count,
                "high_vulnerabilities": high_count,
                "cisa_kev_active_exploits": kev_count,
                "remediation_completion_rate": round(completion_rate, 1),
                "risk_posture": "ELEVATED" if (crit_count > 0 or kev_count > 0) else "NOMINAL"
            },
            "top_exposed_applications": [
                {
                    "name": a.name,
                    "environment": a.environment,
                    "criticality": a.business_criticality,
                    "internet_exposed": a.internet_exposed,
                    "risk_score": a.current_risk_score,
                    "associated_services": [s.name for s in a.business_services]
                }
                for a in sorted(apps, key=lambda x: x.current_risk_score, reverse=True)[:5]
            ],
            "critical_vulnerability_inventory": [
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity,
                    "cvss": v.cvss_v3_score,
                    "is_cisa_kev": v.is_cisa_kev,
                    "epss_score": v.epss_score
                }
                for v in vulns if (v.severity == "CRITICAL" or v.is_cisa_kev)
            ]
        }

    @staticmethod
    def export_vulnerabilities_csv(db: Session) -> str:
        vulns = db.query(Vulnerability).order_by(Vulnerability.cvss_v3_score.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Vulnerability ID", "Title", "Severity", "CVSS v3.1 Score", "CISA KEV Status", "EPSS Score", "Source", "Last Modified"
        ])

        for v in vulns:
            writer.writerow([
                v.id,
                v.title,
                v.severity,
                v.cvss_v3_score,
                "ACTIVE_EXPLOIT" if v.is_cisa_kev else "NO",
                f"{v.epss_score:.4f}",
                v.source,
                v.last_modified_at.isoformat() if v.last_modified_at else ""
            ])

        return output.getvalue()
