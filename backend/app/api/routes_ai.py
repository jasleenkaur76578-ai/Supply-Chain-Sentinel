from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.organization import User
from app.schemas.ai import AIChatRequest, AIChatResponse
from app.security.auth import get_current_user
from app.services.ai_assistant import AISecurityAnalyst
from app.services.audit_service import AuditLoggerService

router = APIRouter(prefix="/ai", tags=["AI Security Assistant"])

@router.post("/chat", response_model=AIChatResponse)
def chat_with_analyst(
    req: AIChatRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    AuditLoggerService.log_event(
        db,
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="AI_ANALYST_QUERY",
        target_resource=req.query[:60],
        details={"query_length": len(req.query)}
    )

    return AISecurityAnalyst.chat(
        db=db,
        query=req.query,
        conversation_id=req.conversation_id or "default"
    )
