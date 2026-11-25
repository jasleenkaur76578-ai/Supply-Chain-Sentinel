from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.database import get_db
from app.models.organization import User, Organization
from app.models.asset import Application
from app.schemas.risk import ApplicationRiskResponse, RiskPolicyUpdate
from app.security.auth import get_current_user, require_role
from app.services.risk_engine import EnterpriseRiskEngine

router = APIRouter(prefix="/risk", tags=["Risk Prioritization"])

@router.get("/applications/{application_id}", response_model=ApplicationRiskResponse)
def get_application_risk(
    application_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    org = db.query(Organization).filter(Organization.id == current_user.org_id).first()
    weights = org.risk_policy.get("weights") if (org and org.risk_policy) else None

    result = EnterpriseRiskEngine.evaluate_application_risk(db, application_id, weights)
    if not result:
        raise HTTPException(status_code=404, detail="Application risk assessment unavailable")
    return result

@router.post("/policy", response_model=Dict[str, Any])
def update_risk_policy(
    policy: RiskPolicyUpdate,
    current_user: User = Depends(require_role(["super_admin", "org_admin"])),
    db: Session = Depends(get_db)
):
    org = db.query(Organization).filter(Organization.id == current_user.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    new_policy = {
        "weights": {
            "cvss_weight": policy.cvss_weight,
            "epss_weight": policy.epss_weight,
            "kev_weight": policy.kev_weight,
            "criticality_weight": policy.criticality_weight,
            "exposure_weight": policy.exposure_weight
        }
    }
    org.risk_policy = new_policy
    db.commit()

    apps = db.query(Application).filter(Application.org_id == org.id).all()
    for app in apps:
        EnterpriseRiskEngine.evaluate_application_risk(db, app.id, new_policy["weights"])

    return {"message": "Risk policy updated and all application risk scores recalculated", "policy": new_policy}
