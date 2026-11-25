from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session, selectinload
from app.models.remediation import RemediationTask, AuditLog
from app.models.sbom import Component
from app.models.vulnerability import ComponentVulnerability

class RemediationService:
    @staticmethod
    def verify_remediation(
        db: Session,
        application_id: str,
        new_sbom_id: str,
        target_vulnerability_id: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        new_components = (
            db.query(Component)
            .filter(Component.sbom_id == new_sbom_id)
            .options(selectinload(Component.vulnerabilities))
            .all()
        )

        is_still_vulnerable = False
        culprit_component = None

        for comp in new_components:
            for cv in comp.vulnerabilities:
                if cv.vulnerability_id == target_vulnerability_id:
                    is_still_vulnerable = True
                    culprit_component = comp
                    break
            if is_still_vulnerable:
                break

        task = (
            db.query(RemediationTask)
            .filter(
                RemediationTask.application_id == application_id,
                RemediationTask.vulnerability_id == target_vulnerability_id
            )
            .first()
        )

        now = datetime.now(timezone.utc)

        if not is_still_vulnerable:
            if task:
                task.status = "RESOLVED"
                task.verified_in_sbom_id = new_sbom_id
                task.updated_at = now

            audit = AuditLog(
                org_id=task.org_id if task else "org-default",
                user_id=user_id,
                action="REMEDIATION_VERIFICATION_SUCCESS",
                target_resource=f"Vulnerability {target_vulnerability_id}",
                details={
                    "application_id": application_id,
                    "new_sbom_id": new_sbom_id,
                    "target_vulnerability_id": target_vulnerability_id,
                    "status": "RESOLVED"
                }
            )
            db.add(audit)
            db.commit()

            return {
                "verified": True,
                "status": "RESOLVED",
                "previous_version": "Vulnerable Version",
                "current_version": "Patched / Removed",
                "residual_risk": "NONE",
                "message": f"Verified successfully! {target_vulnerability_id} is completely eliminated from the new SBOM artifact."
            }
        else:
            if task:
                task.status = "AWAITING_VALIDATION"
                task.updated_at = now

            audit = AuditLog(
                org_id=task.org_id if task else "org-default",
                user_id=user_id,
                action="REMEDIATION_VERIFICATION_FAILED",
                target_resource=f"Vulnerability {target_vulnerability_id}",
                details={
                    "application_id": application_id,
                    "new_sbom_id": new_sbom_id,
                    "culprit": f"{culprit_component.name}@{culprit_component.version}" if culprit_component else "Unknown"
                }
            )
            db.add(audit)
            db.commit()

            return {
                "verified": False,
                "status": "OPEN",
                "previous_version": "Vulnerable",
                "current_version": culprit_component.version if culprit_component else "Vulnerable",
                "residual_risk": "HIGH",
                "message": f"Verification failed: {target_vulnerability_id} is still present in {culprit_component.name if culprit_component else 'dependency'}."
            }
