import os
import sys
import uuid
import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.database import engine, Base, SessionLocal
from app.seed_data import seed_enterprise_demonstration
from app.models.organization import User
from app.schemas.auth import RegisterRequest, UserAdminUpdate
from app.security.auth import get_current_user, require_role, decode_access_token, create_access_token
from app.api.routes_auth import register
from app.api.routes_admin import get_admin_overview, list_users, update_user, get_audit_logs

@pytest.fixture(scope="session", autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_enterprise_demonstration(db)
    yield

def test_unauthenticated_request_rejected():
    """Ensure missing JWT strictly returns HTTP 401 instead of falling back to admin."""
    with SessionLocal() as db:
        with pytest.raises(HTTPException) as exc:
            get_current_user(token=None, db=db)
        assert exc.value.status_code == 401

def test_self_service_registration_and_duplicate_block():
    """Ensure registration creates security_analyst users only and rejects duplicates."""
    unique_email = f"analyst-{uuid.uuid4().hex[:8]}@example.com"
    with SessionLocal() as db:
        res = register(
            RegisterRequest(
                full_name="Test Analyst",
                email=unique_email,
                password="StrongPassword123!"
            ),
            db=db,
        )
        assert res.user.role == "security_analyst"
        assert res.user.email == unique_email
        payload = decode_access_token(res.access_token)
        assert payload["sub"] == res.user.id
        assert payload["role"] == "security_analyst"

        # Duplicate email must fail with 409
        with pytest.raises(HTTPException) as dup_exc:
            register(
                RegisterRequest(
                    full_name="Duplicate Analyst",
                    email=unique_email,
                    password="StrongPassword123!"
                ),
                db=db,
            )
        assert dup_exc.value.status_code == 409

def test_rbac_role_enforcement():
    """Ensure require_role blocks analysts (403) and permits super_admin."""
    checker = require_role(["super_admin", "org_admin"])
    with SessionLocal() as db:
        analyst = db.query(User).filter(User.role == "security_analyst").first()
        admin = db.query(User).filter(User.role == "super_admin").first()
        assert analyst is not None
        assert admin is not None

        with pytest.raises(HTTPException) as exc:
            checker(current_user=analyst)
        assert exc.value.status_code == 403

        assert checker(current_user=admin).id == admin.id

def test_admin_console_endpoints():
    """Verify admin overview, user management, self-demotion protection, and audit logs."""
    with SessionLocal() as db:
        admin = db.query(User).filter(User.role == "super_admin").first()
        assert admin is not None

        ov = get_admin_overview(current_user=admin, db=db)
        assert "database_engine" in ov
        assert ov["total_users"] >= 5

        users = list_users(current_user=admin, db=db)
        assert len(users) >= 5

        # Self-demotion must fail with 400
        with pytest.raises(HTTPException) as exc:
            update_user(
                user_id=admin.id,
                payload=UserAdminUpdate(role="security_analyst"),
                current_user=admin,
                db=db,
            )
        assert exc.value.status_code == 400

        # Updating another user succeeds
        target = next(u for u in users if u.id != admin.id and u.role != "super_admin")
        updated = update_user(
            user_id=target.id,
            payload=UserAdminUpdate(role="security_engineer", is_active=True),
            current_user=admin,
            db=db,
        )
        assert updated.role == "security_engineer"

        logs = get_audit_logs(current_user=admin, db=db)
        assert len(logs) >= 1
        assert any(l["action"] == "ADMIN_USER_UPDATED" for l in logs)

def test_jwt_resolves_by_email_across_containers():
    """Ensure a signed JWT resolves by email if container-local UUID differs."""
    with SessionLocal() as db:
        admin = db.query(User).filter(User.role == "super_admin").first()
        assert admin is not None

        token = create_access_token(data={
            "sub": str(uuid.uuid4()),
            "email": admin.email,
            "full_name": admin.full_name,
            "org_id": admin.org_id,
            "role": admin.role,
        })
        resolved = get_current_user(token=token, db=db)
        assert resolved.email == admin.email
        assert resolved.role == "super_admin"
