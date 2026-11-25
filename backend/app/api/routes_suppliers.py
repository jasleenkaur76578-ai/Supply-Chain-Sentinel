from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session, selectinload
from typing import List
from app.database import get_db
from app.models.organization import User
from app.models.sbom import Supplier
from app.schemas.sbom import SupplierResponse
from app.security.auth import get_current_user

router = APIRouter(prefix="/suppliers", tags=["Supplier Risk"])

@router.get("", response_model=List[SupplierResponse])
def list_suppliers(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    suppliers = db.query(Supplier).filter(Supplier.org_id == current_user.org_id).options(selectinload(Supplier.components)).all()

    return [
        SupplierResponse(
            id=s.id,
            name=s.name,
            contact_email=s.contact_email,
            trust_tier=s.trust_tier,
            security_assessment_score=s.security_assessment_score,
            review_status=s.review_status,
            supplied_components_count=len(s.components)
        )
        for s in suppliers
    ]
