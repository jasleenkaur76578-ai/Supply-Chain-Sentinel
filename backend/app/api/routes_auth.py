from datetime import datetime, timezone
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.organization import User, Organization
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserResponse
from app.security.auth import verify_password, get_password_hash, create_access_token, get_current_user
from app.services.audit_service import AuditLoggerService

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    normalized_email = req.email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password credentials"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended. Contact your platform administrator."
        )

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    org = db.query(Organization).filter(Organization.id == user.org_id).first()
    token = create_access_token(data={"sub": user.id, "org_id": user.org_id, "role": user.role})

    AuditLoggerService.log_event(
        db,
        org_id=user.org_id,
        action="USER_LOGIN_SUCCESS",
        target_resource=user.email,
        user_id=user.id,
        details={"role": user.role}
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=28800,
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            org_id=user.org_id,
            org_name=org.name if org else "Default Organization",
            is_active=user.is_active,
            last_login=user.last_login,
            created_at=user.created_at
        )
    )

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    email = req.email.strip().lower()
    full_name = req.full_name.strip()

    if len(full_name) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Full name must be at least 2 characters."
        )
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid email address."
        )
    if len(req.password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long."
        )

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists."
        )

    org = db.query(Organization).first()
    if not org:
        org = Organization(
            id=str(uuid.uuid4()),
            name="Default Enterprise Organization",
            slug="default-org"
        )
        db.add(org)
        db.flush()

    now = datetime.now(timezone.utc)
    # Self-registered users always start with standard non-admin analyst role
    new_user = User(
        org_id=org.id,
        email=email,
        hashed_password=get_password_hash(req.password),
        full_name=full_name,
        role="security_analyst",
        is_active=True,
        last_login=now
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    token = create_access_token(data={"sub": new_user.id, "org_id": new_user.org_id, "role": new_user.role})

    AuditLoggerService.log_event(
        db,
        org_id=org.id,
        action="USER_REGISTERED",
        target_resource=new_user.email,
        user_id=new_user.id,
        details={"role": new_user.role}
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=28800,
        user=UserResponse(
            id=new_user.id,
            email=new_user.email,
            full_name=new_user.full_name,
            role=new_user.role,
            org_id=new_user.org_id,
            org_name=org.name,
            is_active=new_user.is_active,
            last_login=new_user.last_login,
            created_at=new_user.created_at
        )
    )

@router.get("/me", response_model=UserResponse)
def get_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    org = db.query(Organization).filter(Organization.id == current_user.org_id).first()
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        org_id=current_user.org_id,
        org_name=org.name if org else "Enterprise Organization",
        is_active=current_user.is_active,
        last_login=current_user.last_login,
        created_at=current_user.created_at
    )
