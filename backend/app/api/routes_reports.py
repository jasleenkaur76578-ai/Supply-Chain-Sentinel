from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import Dict, Any
from app.database import get_db
from app.models.organization import User
from app.security.auth import get_current_user
from app.services.reporting_service import ExecutiveReportingService

router = APIRouter(prefix="/reports", tags=["Executive Reporting"])

@router.get("/executive")
def get_executive_report(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    return ExecutiveReportingService.generate_executive_report(db, current_user.org_id)

@router.get("/vulnerabilities/export/csv")
def export_vulnerabilities_csv(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    csv_data = ExecutiveReportingService.export_vulnerabilities_csv(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinel_vulnerability_inventory.csv"}
    )
