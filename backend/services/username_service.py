"""
Username Intelligence Service Layer.
Performs passive concurrent HTTP probes against social and developer platforms to search for a username.
Stores findings and registers IOCs.
"""
import uuid
import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List
import httpx
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_username

logger = logging.getLogger(__name__)


async def check_site(client: httpx.AsyncClient, platform: str, url: str) -> Dict[str, Any]:
    """
    Probes a single site URL for the existence of the username.
    """
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code == 200:
            content = resp.text.lower()
            # Double check common false-positive indicator text in HTML response
            if platform == "Reddit" and ("page not found" in content or "user not found" in content):
                return {"platform": platform, "url": url, "exists": False}
            if platform == "Linktree" and ("page not found" in content or "404" in content):
                return {"platform": platform, "url": url, "exists": False}
            if platform == "Medium" and ("out of order" in content or "404" in content or "not found" in content):
                return {"platform": platform, "url": url, "exists": False}
            return {"platform": platform, "url": url, "exists": True}
        elif resp.status_code == 404:
            return {"platform": platform, "url": url, "exists": False}
        else:
            return {"platform": platform, "url": url, "exists": False, "status_code": resp.status_code}
    except Exception as e:
        logger.debug("Error probing platform %s at %s: %s", platform, url, e)
        return {"platform": platform, "url": url, "exists": False, "error": str(e)}


async def check_username_platforms(username: str) -> List[Dict[str, Any]]:
    """
    Probes popular sites concurrently to check if the username exists.
    """
    platforms = {
        "GitHub": "https://github.com/{username}",
        "Reddit": "https://www.reddit.com/user/{username}",
        "GitLab": "https://gitlab.com/{username}",
        "Medium": "https://medium.com/@{username}",
        "Dev.to": "https://dev.to/{username}",
        "Linktree": "https://linktr.ee/{username}",
        "Pinterest": "https://pinterest.com/{username}",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    async with httpx.AsyncClient(headers=headers, timeout=5.0) as client:
        tasks = []
        for platform, url_template in platforms.items():
            url = url_template.format(username=username)
            tasks.append(check_site(client, platform, url))
        results = await asyncio.gather(*tasks)
    return results


async def analyze_username(db: Session, investigation_id: str, raw_username: str) -> Dict[str, Any]:
    """
    Main Username Intelligence Scanner.
    Validates format, runs passive presence checks, and stores findings/IOCs.
    """
    clean_username = raw_username.strip()
    if not validate_username(clean_username):
        raise ValueError(f"Invalid username target format: '{raw_username}'")

    logger.info("Starting username intelligence footprinting for: %s", clean_username)

    platforms_data = await check_username_platforms(clean_username)

    finding_id = str(uuid.uuid4())

    found_platforms = [r["platform"] for r in platforms_data if r.get("exists") is True]

    scan_result = {
        "finding_id": finding_id,
        "target": clean_username,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "profiles": platforms_data,
        "summary": {
            "total_checked": len(platforms_data),
            "total_found": len(found_platforms),
            "found_platforms": found_platforms,
        },
    }

    # Store finding in database
    finding = Finding(
        id=finding_id,
        investigation_id=investigation_id,
        module="username",
        type="username_scan",
        data=scan_result,
    )
    db.add(finding)

    # Store IOC
    ioc_username = db.query(IOC).filter(IOC.value == clean_username).first()
    if not ioc_username:
        db.add(IOC(value=clean_username, type="username", source="username_module", reputation_score=0.0))

    db.commit()
    db.refresh(finding)

    return scan_result
