"""
OSINT-X backend entrypoint.

Phase 5 scope: core app wiring, CORS, rate limiting, health router,
database table creation, authentication, case management, domain intelligence,
and IP intelligence endpoints.
"""
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from core.config import settings
from core.logging_config import setup_logging
from core.rate_limit import limiter
from database.session import engine, Base
import models  # loads all model definitions

from api.health import router as health_router
from api.auth import router as auth_router
from api.investigations import router as investigations_router
from api.domain import router as domain_router
from api.ip import router as ip_router
from api.email import router as email_router
from api.username import router as username_router
from api.file_intel import router as file_intel_router
from api.threat_intel import router as threat_intel_router
from api.ai_engine import router as ai_engine_router
from api.visualization import router as visualization_router
from api.reports import router as reports_router
from api.audit import router as audit_router
from middleware.security_headers import SecurityHeadersMiddleware

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME, version="0.1.0")

# Attach security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Attach rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(auth_router, prefix="/api")
app.include_router(investigations_router, prefix="/api")
app.include_router(domain_router, prefix="/api")
app.include_router(ip_router, prefix="/api")
app.include_router(email_router, prefix="/api")
app.include_router(username_router, prefix="/api")
app.include_router(file_intel_router, prefix="/api")
app.include_router(threat_intel_router, prefix="/api")
app.include_router(ai_engine_router, prefix="/api")
app.include_router(visualization_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(audit_router, prefix="/api")




@app.on_event("startup")
def on_startup():
    logger.info("%s starting up in '%s' mode", settings.APP_NAME, settings.APP_ENV)
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully.")
    except Exception as e:
        logger.warning("Could not auto-initialize DB tables on startup (PostgreSQL might be starting): %s", e)


@app.get("/")
def root():
    return {"message": "OSINT-X API is running. See /docs for the API reference."}
