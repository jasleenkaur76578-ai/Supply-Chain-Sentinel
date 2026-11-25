from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
import os
from app.config import settings
from app.database import engine, Base, SessionLocal
from app.seed_data import seed_enterprise_demonstration
from app.api.routes_auth import router as auth_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_assets import router as assets_router
from app.api.routes_sbom import router as sbom_router
from app.api.routes_vulnerabilities import router as vuln_router
from app.api.routes_graph import router as graph_router
from app.api.routes_propagation import router as propagation_router
from app.api.routes_risk import router as risk_router
from app.api.routes_ai import router as ai_router
from app.api.routes_remediation import router as remediation_router
from app.api.routes_suppliers import router as suppliers_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_reports import router as reports_router
from app.api.routes_admin import router as admin_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database Tables
    logger.info("Initializing Supply Chain Sentinel Database Engine...")
    Base.metadata.create_all(bind=engine)

    # Seed demonstration environment
    logger.info("Checking and seeding enterprise demonstration environment...")
    with SessionLocal() as session:
        seed_enterprise_demonstration(session)
    logger.info("Supply Chain Sentinel Backend ready.")
    yield
    # Shutdown
    logger.info("Shutting down database connection pool...")
    engine.dispose()

is_production = settings.ENVIRONMENT.lower() == "production"

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-Grade AI-Powered Software Supply Chain Risk Intelligence & Attack Propagation Platform",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
    lifespan=lifespan
)

if os.environ.get("VERCEL"):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as _session:
        seed_enterprise_demonstration(_session)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pure ASGI Enterprise Security Headers Middleware (Avoids BaseHTTPMiddleware threadpool deadlocks)
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-content-type-options", b"nosniff"))
                headers.append((b"x-frame-options", b"DENY"))
                headers.append((b"x-xss-protection", b"1; mode=block"))
                headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                headers.append((b"referrer-policy", b"strict-origin-when-cross-origin"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

app.add_middleware(SecurityHeadersMiddleware)

# Register Routers
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(assets_router, prefix=settings.API_V1_STR)
app.include_router(sbom_router, prefix=settings.API_V1_STR)
app.include_router(vuln_router, prefix=settings.API_V1_STR)
app.include_router(graph_router, prefix=settings.API_V1_STR)
app.include_router(propagation_router, prefix=settings.API_V1_STR)
app.include_router(risk_router, prefix=settings.API_V1_STR)
app.include_router(ai_router, prefix=settings.API_V1_STR)
app.include_router(remediation_router, prefix=settings.API_V1_STR)
app.include_router(suppliers_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(admin_router, prefix=settings.API_V1_STR)

@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "HEALTHY",
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }

@app.get("/", tags=["Root"])
def root():
    return {
        "name": settings.PROJECT_NAME,
        "tagline": "See the Risk. Trace the Impact. Stop the Spread.",
        "documentation": "/docs",
        "api_v1": settings.API_V1_STR
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
