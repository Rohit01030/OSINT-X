"""
Email Intelligence Service Layer.
Performs passive checks on email domains (MX, SPF, DMARC, DKIM) and query breach databases.
Stores findings and registers IOCs.
"""
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
import dns.resolver
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_email
from core.config import settings

logger = logging.getLogger(__name__)


def check_email_security(email: str) -> Dict[str, Any]:
    """
    Checks MX, SPF, DMARC, and common DKIM selectors for the domain of the email.
    """
    domain = email.split("@")[1].strip().lower()
    result: Dict[str, Any] = {
        "domain": domain,
        "mx": [],
        "spf": None,
        "dmarc": None,
        "dkim": [],
        "warnings": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # 1. Query MX records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        result["mx"] = [
            {"preference": r.preference, "exchange": str(r.exchange).rstrip(".")}
            for r in mx_answers
        ]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception) as e:
        result["warnings"].append(f"Could not resolve MX records: {str(e)}")

    # 2. Query SPF (TXT records starting with v=spf1)
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for r in txt_answers:
            txt_content = b"".join(r.strings).decode("utf-8", errors="ignore")
            if txt_content.startswith("v=spf1"):
                result["spf"] = txt_content
                break
    except Exception:
        pass

    # 3. Query DMARC (TXT record on _dmarc.domain starting with v=DMARC1)
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_answers:
            txt_content = b"".join(r.strings).decode("utf-8", errors="ignore")
            if txt_content.startswith("v=DMARC1"):
                result["dmarc"] = txt_content
                break
    except Exception:
        pass

    # 4. Check common DKIM selectors (default, google, mail, k1)
    common_selectors = ["default", "google", "mail", "k1"]
    for sel in common_selectors:
        try:
            dkim_answers = resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
            for r in dkim_answers:
                txt_content = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=DKIM1" in txt_content or "k=rsa" in txt_content:
                    result["dkim"].append({"selector": sel, "record": txt_content})
        except Exception:
            pass

    return result


def check_email_breaches(email: str) -> List[Dict[str, Any]]:
    """
    Checks Have I Been Pwned (HIBP) API for email breaches.
    If HIBP_API_KEY is not set, runs in simulation mode.
    """
    if not settings.HIBP_API_KEY:
        # Simulation Mode
        simulated_emails = ["breached@example.com", "test@example.com"]
        if email.strip().lower() in simulated_emails:
            return [
                {
                    "Name": "Adobe",
                    "Title": "Adobe",
                    "Domain": "adobe.com",
                    "BreachDate": "2013-10-04",
                    "Description": "In October 2013, Adobe suffered a major data breach...",
                    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
                },
                {
                    "Name": "Canva",
                    "Title": "Canva",
                    "Domain": "canva.com",
                    "BreachDate": "2019-05-24",
                    "Description": "In May 2019, Canva suffered a data breach...",
                    "DataClasses": ["Email addresses", "Names", "Passwords", "Usernames"],
                }
            ]
        return []

    # Real check using HIBP API
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email.strip()}"
    headers = {
        "hibp-api-key": settings.HIBP_API_KEY,
        "user-agent": "OSINT-X-Platform",
    }

    try:
        with httpx.Client(timeout=6.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return []
            else:
                logger.warning("HIBP API returned status code %s", resp.status_code)
                return []
    except Exception as e:
        logger.error("Error querying HIBP API: %s", e)
        return []


def analyze_email(db: Session, investigation_id: str, raw_email: str) -> Dict[str, Any]:
    """
    Main Email Intelligence Scanner.
    Validates format, runs DNS security audits & breach checks, and stores findings/IOCs.
    """
    clean_email = raw_email.strip().lower()
    if not validate_email(clean_email):
        raise ValueError(f"Invalid email target format: '{raw_email}'")

    logger.info("Starting email intelligence scan for: %s", clean_email)

    security_data = check_email_security(clean_email)
    breaches_data = check_email_breaches(clean_email)

    finding_id = str(uuid.uuid4())

    scan_result = {
        "finding_id": finding_id,
        "target": clean_email,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "email_security": security_data,
        "breaches": breaches_data,
        "simulation_mode": settings.HIBP_API_KEY is None,
        "summary": {
            "mx_found": len(security_data["mx"]) > 0,
            "spf_valid": security_data["spf"] is not None,
            "dmarc_valid": security_data["dmarc"] is not None,
            "breach_count": len(breaches_data),
        },
    }

    # Store finding
    finding = Finding(
        id=finding_id,
        investigation_id=investigation_id,
        module="email",
        type="email_scan",
        data=scan_result,
    )
    db.add(finding)

    # Store IOCs (Email and its domain)
    ioc_email = db.query(IOC).filter(IOC.value == clean_email).first()
    if not ioc_email:
        db.add(IOC(value=clean_email, type="email", source="email_module", reputation_score=0.0))

    domain = security_data["domain"]
    ioc_domain = db.query(IOC).filter(IOC.value == domain).first()
    if not ioc_domain:
        db.add(IOC(value=domain, type="domain", source="email_module", reputation_score=0.0))

    db.commit()
    db.refresh(finding)

    return scan_result
