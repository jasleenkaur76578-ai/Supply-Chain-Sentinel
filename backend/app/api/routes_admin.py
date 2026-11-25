from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db, database_url
from app.models.organization import User
from app.models.asset import Application
from app.models.sbom import SBOMDocument
from app.models.vulnerability import Vulnerability
from app.models.remediation import AuditLog, SecurityAlert
from app.schemas.auth import UserResponse, UserAdminUpdate
from app.security.auth import require_role
from app.services.audit_service import AuditLoggerService

router = APIRouter(prefix="/admin", tags=["Administration"])

ALLOWED_ROLES = {
    "super_admin",
    "org_admin",
    "security_analyst",
    "security_engineer",
    "read_only_exec",
}

@router.get("/overview", response_model=Dict[str, Any])
def get_admin_overview(
    current_user: User = Depends(require_role(["super_admin", "org_admin"])),
    db: Session = Depends(get_db),
):
    org_id = current_user.org_id
    db_engine = "PostgreSQL" if "postgres" in database_url.lower() else "SQLite"

    total_users = db.query(User).filter(User.org_id == org_id).count()
    active_users = db.query(User).filter(User.org_id == org_id, User.is_active == True).count()
    total_applications = db.query(Application).filter(Application.org_id == org_id).count()
    total_sboms = (
        db.query(SBOMDocument)
        .join(Application, SBOMDocument.application_id == Application.id)
        .filter(Application.org_id == org_id)
        .count()
    )
    total_vulnerabilities = db.query(Vulnerability).count()
    total_audit_logs = db.query(AuditLog).filter(AuditLog.org_id == org_id).count()
    unacknowledged_alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.org_id == org_id, SecurityAlert.is_acknowledged == False)
        .count()
    )

    return {
        "environment": settings.ENVIRONMENT,
        "database_engine": db_engine,
        "total_users": total_users,
        "active_users": active_users,
        "total_applications": total_applications,
        "total_sboms": total_sboms,
        "total_vulnerabilities": total_vulnerabilities,
        "total_audit_logs": total_audit_logs,
        "unacknowledged_alerts": unacknowledged_alerts,
        "docs_enabled": settings.ENVIRONMENT != "production",
    }

@router.get("/users", response_model=List[UserResponse])
def list_users(
    current_user: User = Depends(require_role(["super_admin", "org_admin"])),
    db: Session = Depends(get_db),
):
    users = (
        db.query(User)
        .filter(User.org_id == current_user.org_id)
        .order_by(User.created_at.asc())
        .all()
    )
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            org_id=u.org_id,
            is_active=u.is_active,
            last_login=u.last_login,
            created_at=u.created_at,
        )
        for u in users
    ]

@router.patch("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: str,
    payload: UserAdminUpdate,
    current_user: User = Depends(require_role(["super_admin", "org_admin"])),
    db: Session = Depends(get_db),
):
    target_user = (
        db.query(User)
        .filter(User.id == user_id, User.org_id == current_user.org_id)
        .first()
    )
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if payload.role is not None:
        if payload.role not in ALLOWED_ROLES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role '{payload.role}'. Allowed: {sorted(ALLOWED_ROLES)}",
            )
        if target_user.id == current_user.id and payload.role not in ("super_admin", "org_admin"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot remove their own admin role.",
            )
        target_user.role = payload.role

    if payload.is_active is not None:
        if target_user.id == current_user.id and not payload.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot deactivate their own account.",
            )
        target_user.is_active = payload.is_active

    db.commit()
    db.refresh(target_user)

    AuditLoggerService.log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="ADMIN_USER_UPDATED",
        target_resource=target_user.email,
        details={"role": target_user.role, "is_active": target_user.is_active},
    )

    return UserResponse(
        id=target_user.id,
        email=target_user.email,
        full_name=target_user.full_name,
        role=target_user.role,
        org_id=target_user.org_id,
        is_active=target_user.is_active,
        last_login=target_user.last_login,
        created_at=target_user.created_at,
    )

@router.get("/audit-logs", response_model=List[Dict[str, Any]])
def get_audit_logs(
    current_user: User = Depends(require_role(["super_admin", "org_admin"])),
    db: Session = Depends(get_db),
):
    logs = (
        db.query(AuditLog)
        .filter(AuditLog.org_id == current_user.org_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(50)
        .all()
    )
    user_ids = {log.user_id for log in logs if log.user_id}
    user_map = {}
    if user_ids:
        users = db.query(User).filter(User.id.in_(user_ids)).all()
        user_map = {u.id: u.email for u in users}

    return [
        {
            "id": log.id,
            "action": log.action,
            "user_id": log.user_id,
            "user_email": user_map.get(log.user_id, "System"),
            "target_resource": log.target_resource,
            "details": log.details or {},
            "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        }
        for log in logs
    ]
