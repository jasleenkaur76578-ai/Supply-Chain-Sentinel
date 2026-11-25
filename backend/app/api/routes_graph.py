from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.database import get_db
from app.models.organization import User
from app.security.auth import get_current_user
from app.services.graph_engine import DependencyGraphEngine

router = APIRouter(prefix="/graph", tags=["Dependency Graph"])

@router.get("/application/{application_id}")
def get_application_dependency_graph(
    application_id: str,
    max_depth: int = Query(default=5, ge=1, le=10),
    include_vulnerabilities: bool = Query(default=True),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    return DependencyGraphEngine.build_application_graph(
        db,
        application_id=application_id,
        max_depth=max_depth,
        include_vulnerabilities=include_vulnerabilities
    )
