from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, selectinload
from typing import List, Optional
from app.database import get_db
from app.models.organization import User
from app.models.asset import Application, BusinessService
from app.schemas.asset import ApplicationCreate, ApplicationResponse, BusinessServiceCreate, BusinessServiceResponse
from app.security.auth import get_current_user, require_role
from app.services.audit_service import AuditLoggerService

router = APIRouter(prefix="/assets", tags=["Asset Inventory"])

@router.get("/applications", response_model=List[ApplicationResponse])
def list_applications(
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Application).filter(Application.org_id == current_user.org_id).options(selectinload(Application.business_services))
    if environment:
        query = query.filter(Application.environment == environment)
    if criticality:
        query = query.filter(Application.business_criticality == criticality)
    return query.all()

@router.get("/applications/{application_id}", response_model=ApplicationResponse)
def get_application(
    application_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    app = (
        db.query(Application)
        .filter(Application.id == application_id, Application.org_id == current_user.org_id)
        .options(selectinload(Application.business_services))
        .first()
    )
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return app

@router.post("/applications", response_model=ApplicationResponse)
def create_application(
    req: ApplicationCreate,
    current_user: User = Depends(require_role(["super_admin", "org_admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    new_app = Application(
        org_id=current_user.org_id,
        name=req.name,
        repository_url=req.repository_url,
        environment=req.environment,
        business_criticality=req.business_criticality,
        internet_exposed=req.internet_exposed
    )
    db.add(new_app)
    db.flush()

    if req.business_service_ids:
        services = db.query(BusinessService).filter(BusinessService.id.in_(req.business_service_ids)).all()
        new_app.business_services = list(services)

    db.commit()
    db.refresh(new_app)

    AuditLoggerService.log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="APPLICATION_CREATED",
        target_resource=new_app.name,
        details={"app_id": new_app.id, "environment": new_app.environment}
    )

    return get_application(new_app.id, current_user, db)

@router.get("/services", response_model=List[BusinessServiceResponse])
def list_business_services(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(BusinessService).filter(BusinessService.org_id == current_user.org_id).all()

@router.post("/services", response_model=BusinessServiceResponse)
def create_business_service(
    req: BusinessServiceCreate,
    current_user: User = Depends(require_role(["super_admin", "org_admin", "security_engineer"])),
    db: Session = Depends(get_db)
):
    srv = BusinessService(
        org_id=current_user.org_id,
        name=req.name,
        criticality=req.criticality,
        financial_impact_rating=req.financial_impact_rating,
        owner_team=req.owner_team
    )
    db.add(srv)
    db.commit()
    db.refresh(srv)
    return srv
