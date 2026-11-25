from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.organization import User
from app.schemas.propagation import PropagationRequest, PropagationAnalysisResponse
from app.security.auth import get_current_user
from app.services.blast_radius import BlastRadiusPropagationEngine

router = APIRouter(prefix="/propagation", tags=["Attack Propagation"])

@router.post("/analyze", response_model=PropagationAnalysisResponse)
def analyze_attack_propagation(
    req: PropagationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return BlastRadiusPropagationEngine.analyze_propagation(
        db=db,
        org_id=current_user.org_id,
        package_name=req.component_name,
        package_version=req.component_version,
        vulnerability_id=req.vulnerability_id,
        component_id=req.component_id
    )
