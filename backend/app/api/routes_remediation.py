from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from app.database import get_db
from app.models.organization import User
from app.models.remediation import RemediationTask
from app.models.asset import Application
from app.models.sbom import Component
from app.models.vulnerability import Vulnerability
from app.schemas.remediation import (
    RemediationTaskCreate,
    RemediationTaskUpdate,
    RemediationTaskResponse,
    RemediationVerifyRequest,
    RemediationVerifyResponse
)
from app.security.auth import get_current_user, require_role
from app.services.remediation_service import RemediationService
from app.services.audit_service import AuditLoggerService

router = APIRouter(prefix="/remediation", tags=["Remediation Management"])

@router.get("/tasks", response_model=List[RemediationTaskResponse])
def list_tasks(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = (
        db.query(RemediationTask)
        .filter(RemediationTask.org_id == current_user.org_id)
        .options(selectinload(RemediationTask.application))
        .order_by(RemediationTask.created_at.desc())
    )
    if status:
        query = query.filter(RemediationTask.status == status.upper())
    if priority:
        query = query.filter(RemediationTask.priority == priority.upper())

    tasks = query.all()

    results = []
    for t in tasks:
        comp = db.query(Component).filter(Component.id == t.component_id).first()
        vuln = db.query(Vulnerability).filter(Vulnerability.id == t.vulnerability_id).first()

        results.append(RemediationTaskResponse(
            id=t.id,
            org_id=t.org_id,
            application_id=t.application_id,
            application_name=t.application.name if t.application else "Unknown App",
            component_id=t.component_id,
            component_name=comp.name if comp else "Unknown Package",
            component_version=comp.version if comp else "0.0.0",
            vulnerability_id=t.vulnerability_id,
            vulnerability_severity=vuln.severity if vuln else "MEDIUM",
            title=t.title,
            description=t.description,
            priority=t.priority,
            status=t.status,
            assigned_team=t.assigned_team,
            target_resolution_date=t.target_resolution_date,
            recommended_version=t.recommended_version,
            verified_in_sbom_id=t.verified_in_sbom_id,
            compensating_controls=t.compensating_controls,
            risk_acceptance_justification=t.risk_acceptance_justification,
            created_at=t.created_at,
            updated_at=t.updated_at
        ))

    return results

@router.post("/tasks", response_model=RemediationTaskResponse)
def create_task(
    req: RemediationTaskCreate,
    current_user: User = Depends(require_role(["super_admin", "org_admin", "security_engineer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    new_task = RemediationTask(
        org_id=current_user.org_id,
        application_id=req.application_id,
        component_id=req.component_id,
        vulnerability_id=req.vulnerability_id,
        title=req.title,
        description=req.description,
        priority=req.priority,
        status="OPEN",
        assigned_team=req.assigned_team,
        target_resolution_date=req.target_resolution_date,
        recommended_version=req.recommended_version,
        compensating_controls=req.compensating_controls
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    AuditLoggerService.log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="REMEDIATION_TASK_CREATED",
        target_resource=new_task.title,
        details={"task_id": new_task.id, "vulnerability": req.vulnerability_id}
    )

    comp = db.query(Component).filter(Component.id == new_task.component_id).first()
    app = db.query(Application).filter(Application.id == new_task.application_id).first()
    vuln = db.query(Vulnerability).filter(Vulnerability.id == new_task.vulnerability_id).first()

    return RemediationTaskResponse(
        id=new_task.id,
        org_id=new_task.org_id,
        application_id=new_task.application_id,
        application_name=app.name if app else "Unknown",
        component_id=new_task.component_id,
        component_name=comp.name if comp else "Unknown",
        component_version=comp.version if comp else "0.0.0",
        vulnerability_id=new_task.vulnerability_id,
        vulnerability_severity=vuln.severity if vuln else "MEDIUM",
        title=new_task.title,
        description=new_task.description,
        priority=new_task.priority,
        status=new_task.status,
        assigned_team=new_task.assigned_team,
        target_resolution_date=new_task.target_resolution_date,
        recommended_version=new_task.recommended_version,
        verified_in_sbom_id=new_task.verified_in_sbom_id,
        compensating_controls=new_task.compensating_controls,
        risk_acceptance_justification=new_task.risk_acceptance_justification,
        created_at=new_task.created_at,
        updated_at=new_task.updated_at
    )

@router.patch("/tasks/{task_id}", response_model=Dict[str, Any])
def update_task(
    task_id: str,
    req: RemediationTaskUpdate,
    current_user: User = Depends(require_role(["super_admin", "org_admin", "security_engineer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id, RemediationTask.org_id == current_user.org_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found")

    if req.status:
        task.status = req.status.upper()
    if req.assigned_team:
        task.assigned_team = req.assigned_team
    if req.priority:
        task.priority = req.priority.upper()
    if req.target_resolution_date:
        task.target_resolution_date = req.target_resolution_date
    if req.compensating_controls is not None:
        task.compensating_controls = req.compensating_controls
    if req.risk_acceptance_justification is not None:
        task.risk_acceptance_justification = req.risk_acceptance_justification

    task.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"message": "Remediation task updated successfully", "task_id": task.id, "status": task.status}

@router.post("/verify", response_model=RemediationVerifyResponse)
def verify_remediation(
    req: RemediationVerifyRequest,
    current_user: User = Depends(require_role(["super_admin", "org_admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    return RemediationService.verify_remediation(
        db=db,
        application_id=req.application_id,
        new_sbom_id=req.new_sbom_id,
        target_vulnerability_id=req.target_vulnerability_id,
        user_id=current_user.id
    )
