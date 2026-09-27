"""
Celery background worker application configuration.

Handles asynchronous task execution for long-running recon scans and external API queries.
"""
import logging
from celery import Celery
from core.config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "osintx",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 min hard limit for deep scans
)

# Example ping/health task
@celery_app.task(name="tasks.ping")
def ping_task() -> str:
    logger.info("Celery worker ping received.")
    return "pong"
