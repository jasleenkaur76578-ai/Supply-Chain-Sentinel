from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.organization import User
from app.models.remediation import SecurityAlert
from app.security.auth import get_current_user

router = APIRouter(prefix="/alerts", tags=["Continuous Monitoring & Alerts"])

@router.get("")
def list_alerts(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(SecurityAlert).filter(SecurityAlert.org_id == current_user.org_id).order_by(SecurityAlert.created_at.desc()).all()

@router.post("/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id, SecurityAlert.org_id == current_user.org_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_acknowledged = True
    alert.acknowledged_by = current_user.id
    db.commit()
    return {"message": "Alert acknowledged successfully", "alert_id": alert.id}
