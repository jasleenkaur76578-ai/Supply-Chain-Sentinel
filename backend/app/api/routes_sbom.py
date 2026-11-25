from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from sqlalchemy.orm import Session, selectinload
from typing import List, Optional
from app.database import get_db
from app.models.organization import User
from app.models.asset import Application
from app.models.sbom import SBOMDocument, Component, DependencyRelationship, Supplier
from app.models.vulnerability import Vulnerability, ComponentVulnerability
from app.schemas.sbom import SBOMUploadResponse, SBOMDetailResponse, ComponentResponse
from app.security.auth import get_current_user, require_role
from app.services.sbom_parser import SBOMParser
from app.services.vuln_intel import VulnerabilityIntelligenceEngine
from app.services.risk_engine import EnterpriseRiskEngine
from app.services.audit_service import AuditLoggerService

router = APIRouter(prefix="/sbom", tags=["SBOM Analyzer"])

MAX_SBOM_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB

@router.post("/upload", response_model=SBOMUploadResponse)
async def upload_sbom(
    application_id: str = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(require_role(["super_admin", "org_admin", "security_engineer", "security_analyst"])),
    db: Session = Depends(get_db)
):
    app = db.query(Application).filter(Application.id == application_id, Application.org_id == current_user.org_id).first()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found or unauthorized")

    content = await file.read()
    if len(content) > MAX_SBOM_SIZE_BYTES:
        raise HTTPException(status_code=400, detail="Uploaded file exceeds 25MB enterprise limit")

    try:
        parsed = SBOMParser.parse_sbom(content, file.filename or "sbom.json")
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {str(e)}")

    prev_sboms = db.query(SBOMDocument).filter(SBOMDocument.application_id == application_id).all()
    for s in prev_sboms:
        s.is_latest = False

    new_sbom = SBOMDocument(
        application_id=application_id,
        format=parsed["format"],
        spec_version=parsed["spec_version"],
        serial_number=parsed.get("serial_number", ""),
        file_hash_sha256=parsed["file_hash_sha256"],
        file_name=parsed["file_name"],
        component_count=len(parsed["components"]),
        dependency_count=len(parsed["relationships"]),
        is_latest=True,
        raw_content=parsed["raw_content"][:50000]
    )
    db.add(new_sbom)
    db.flush()

    ref_to_component_id = {}
    saved_components = []

    for comp_data in parsed["components"]:
        supplier_id = None
        sup_name = comp_data.get("supplier_name")
        if sup_name and sup_name != "Open Source Community":
            sup = db.query(Supplier).filter(Supplier.name == sup_name, Supplier.org_id == current_user.org_id).first()
            if not sup:
                sup = Supplier(org_id=current_user.org_id, name=sup_name, trust_tier="TIER_2_STANDARD")
                db.add(sup)
                db.flush()
            supplier_id = sup.id

        comp = Component(
            sbom_id=new_sbom.id,
            supplier_id=supplier_id,
            purl=comp_data["purl"],
            name=comp_data["name"],
            version=comp_data["version"],
            ecosystem=comp_data["ecosystem"],
            license_declared=comp_data["license_declared"],
            is_direct=comp_data["is_direct"],
            depth=comp_data["depth"]
        )
        db.add(comp)
        db.flush()
        saved_components.append(comp)
        ref_to_component_id[comp_data["bom_ref"]] = comp.id
        ref_to_component_id[comp_data["name"]] = comp.id

    for rel in parsed["relationships"]:
        p_id = ref_to_component_id.get(rel["parent_ref"])
        c_id = ref_to_component_id.get(rel["child_ref"])
        if p_id and c_id and p_id != c_id:
            dep_rel = DependencyRelationship(
                sbom_id=new_sbom.id,
                parent_component_id=p_id,
                child_component_id=c_id,
                relationship_type=rel.get("type", "DEPENDS_ON")
            )
            db.add(dep_rel)

    vulnerabilities_detected = 0
    critical_count = 0

    for comp in saved_components:
        vuln_intel_list = await VulnerabilityIntelligenceEngine.query_osv(
            package_name=comp.name,
            version=comp.version,
            ecosystem=comp.ecosystem
        )

        for v_data in vuln_intel_list:
            vulnerabilities_detected += 1
            if v_data["severity"] == "CRITICAL" or v_data["is_cisa_kev"]:
                critical_count += 1

            vuln_obj = db.query(Vulnerability).filter(Vulnerability.id == v_data["id"]).first()
            if not vuln_obj:
                vuln_obj = Vulnerability(
                    id=v_data["id"],
                    source=v_data["source"],
                    title=v_data["title"],
                    summary=v_data["summary"],
                    details=v_data["details"],
                    cvss_v3_score=v_data["cvss_v3_score"],
                    cvss_v3_vector=v_data["cvss_v3_vector"],
                    severity=v_data["severity"],
                    epss_score=v_data["epss_score"],
                    epss_percentile=v_data["epss_percentile"],
                    is_cisa_kev=v_data["is_cisa_kev"]
                )
                db.add(vuln_obj)
                db.flush()

            cv = ComponentVulnerability(
                component_id=comp.id,
                vulnerability_id=vuln_obj.id,
                verification_status="POTENTIAL_EXPOSURE",
                remediation_available=True,
                fixed_version=v_data.get("fixed_version", "")
            )
            db.add(cv)

    app.active_sbom_id = new_sbom.id
    db.commit()

    EnterpriseRiskEngine.evaluate_application_risk(db, application_id)

    AuditLoggerService.log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="SBOM_UPLOAD_PROCESSED",
        target_resource=app.name,
        details={
            "sbom_id": new_sbom.id,
            "components_count": len(saved_components),
            "vulnerabilities_detected": vulnerabilities_detected,
            "critical_count": critical_count
        }
    )

    return SBOMUploadResponse(
        sbom_id=new_sbom.id,
        application_id=application_id,
        format=new_sbom.format,
        spec_version=new_sbom.spec_version,
        file_name=new_sbom.file_name,
        components_parsed=len(saved_components),
        dependencies_parsed=len(parsed["relationships"]),
        vulnerabilities_detected=vulnerabilities_detected,
        critical_count=critical_count,
        parsing_warnings=parsed.get("warnings", [])
    )

@router.get("/{sbom_id}/report", response_model=SBOMDetailResponse)
def get_sbom_report(
    sbom_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    sbom = (
        db.query(SBOMDocument)
        .filter(SBOMDocument.id == sbom_id)
        .options(
            selectinload(SBOMDocument.application),
            selectinload(SBOMDocument.components).selectinload(Component.vulnerabilities).selectinload(ComponentVulnerability.vulnerability)
        )
        .first()
    )
    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM document not found")

    comp_responses = []
    for c in sbom.components:
        v_count = len(c.vulnerabilities)
        max_sev = "NONE"
        for cv in c.vulnerabilities:
            if cv.vulnerability:
                sev = cv.vulnerability.severity
                if sev == "CRITICAL" or cv.vulnerability.is_cisa_kev:
                    max_sev = "CRITICAL"
                    break
                elif sev == "HIGH" and max_sev != "CRITICAL":
                    max_sev = "HIGH"
                elif sev == "MEDIUM" and max_sev not in ("CRITICAL", "HIGH"):
                    max_sev = "MEDIUM"

        comp_responses.append(ComponentResponse(
            id=c.id,
            sbom_id=c.sbom_id,
            purl=c.purl,
            name=c.name,
            version=c.version,
            ecosystem=c.ecosystem,
            license_declared=c.license_declared,
            is_direct=c.is_direct,
            depth=c.depth,
            vulnerability_count=v_count,
            max_severity=max_sev if v_count > 0 else None
        ))

    return SBOMDetailResponse(
        id=sbom.id,
        application_id=sbom.application_id,
        application_name=sbom.application.name if sbom.application else "Unknown",
        format=sbom.format,
        spec_version=sbom.spec_version,
        file_name=sbom.file_name,
        component_count=len(comp_responses),
        dependency_count=sbom.dependency_count,
        is_latest=sbom.is_latest,
        created_at=sbom.created_at,
        components=comp_responses
    )
