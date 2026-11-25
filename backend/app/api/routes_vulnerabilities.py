from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload
from typing import List, Optional
from app.database import get_db
from app.models.organization import User
from app.models.vulnerability import Vulnerability, ComponentVulnerability
from app.models.sbom import Component, SBOMDocument
from app.schemas.vulnerability import VulnerabilityResponse
from app.security.auth import get_current_user

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Intelligence"])

@router.get("", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[str] = None,
    is_kev: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Vulnerability).order_by(Vulnerability.cvss_v3_score.desc())
    if severity:
        query = query.filter(Vulnerability.severity == severity.upper())
    if is_kev is not None:
        query = query.filter(Vulnerability.is_cisa_kev == is_kev)
    if search:
        query = query.filter(
            (Vulnerability.id.ilike(f"%{search}%")) |
            (Vulnerability.title.ilike(f"%{search}%")) |
            (Vulnerability.summary.ilike(f"%{search}%"))
        )

    vulns = query.all()

    all_cv = (
        db.query(ComponentVulnerability)
        .options(
            selectinload(ComponentVulnerability.component)
            .selectinload(Component.sbom)
            .selectinload(SBOMDocument.application)
        )
        .all()
    )

    results = []
    for v in vulns:
        matched_apps = set()
        matched_comps = 0
        for cv in all_cv:
            if cv.vulnerability_id == v.id:
                matched_comps += 1
                if cv.component and cv.component.sbom and cv.component.sbom.application:
                    matched_apps.add(cv.component.sbom.application.name)

        results.append(VulnerabilityResponse(
            id=v.id,
            source=v.source,
            title=v.title,
            summary=v.summary,
            details=v.details,
            cvss_v3_score=v.cvss_v3_score,
            cvss_v3_vector=v.cvss_v3_vector,
            severity=v.severity,
            epss_score=v.epss_score,
            epss_percentile=v.epss_percentile,
            is_cisa_kev=v.is_cisa_kev,
            cisa_kev_due_date=v.cisa_kev_due_date,
            affected_packages=v.affected_packages or [],
            published_at=v.published_at,
            last_modified_at=v.last_modified_at,
            affected_components_count=matched_comps,
            affected_applications=list(matched_apps)
        ))

    return results

@router.get("/{vulnerability_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vulnerability_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    v = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    cv_list = (
        db.query(ComponentVulnerability)
        .filter(ComponentVulnerability.vulnerability_id == v.id)
        .options(
            selectinload(ComponentVulnerability.component)
            .selectinload(Component.sbom)
            .selectinload(SBOMDocument.application)
        )
        .all()
    )
    matched_apps = list(set(
        cv.component.sbom.application.name
        for cv in cv_list
        if cv.component and cv.component.sbom and cv.component.sbom.application
    ))

    return VulnerabilityResponse(
        id=v.id,
        source=v.source,
        title=v.title,
        summary=v.summary,
        details=v.details,
        cvss_v3_score=v.cvss_v3_score,
        cvss_v3_vector=v.cvss_v3_vector,
        severity=v.severity,
        epss_score=v.epss_score,
        epss_percentile=v.epss_percentile,
        is_cisa_kev=v.is_cisa_kev,
        cisa_kev_due_date=v.cisa_kev_due_date,
        affected_packages=v.affected_packages or [],
        published_at=v.published_at,
        last_modified_at=v.last_modified_at,
        affected_components_count=len(cv_list),
        affected_applications=matched_apps
    )
