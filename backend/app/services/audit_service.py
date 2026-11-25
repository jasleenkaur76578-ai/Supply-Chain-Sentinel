from typing import Dict, Any, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.remediation import AuditLog

class AuditLoggerService:
    @staticmethod
    def log_event(
        db: Session,
        org_id: str,
        action: str,
        target_resource: str = "",
        user_id: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None
    ) -> AuditLog:
        audit = AuditLog(
            org_id=org_id,
            user_id=user_id,
            action=action,
            target_resource=target_resource,
            ip_address=ip_address,
            details=details or {},
            timestamp=datetime.now(timezone.utc)
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)
        return audit
