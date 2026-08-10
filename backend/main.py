"""
OSINT-X backend entrypoint.

Phase 3 scope: core app wiring, CORS, rate limiting, health router,
database table creation, authentication, and investigation case management endpoints.
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

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME, version="0.1.0")

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
