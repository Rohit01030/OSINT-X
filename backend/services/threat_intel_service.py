"""
Threat Intelligence Service Layer.
Integrates third-party threat intel APIs (VirusTotal, AbuseIPDB, Shodan) to check target reputations.
Computes a unified threat/reputation score, saves findings, and updates the IOC database.
"""
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_ip, validate_domain, validate_hash, sanitize_target
from core.config import settings

logger = logging.getLogger(__name__)


def check_virustotal(target: str, target_type: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 API for the target (IP, Domain, or Hash).
    Runs in simulation mode if VIRUSTOTAL_API_KEY is not set.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        # Simulation Mode
        is_malicious = False
        malicious_targets = ["malicious.com", "1.1.1.1", "8b80ea740134bc5b1b467e100f7db9d16bba404f355b22102e4718a388555162"]
        
        if target.strip().lower() in malicious_targets:
            is_malicious = True

        return {
            "data": {
                "id": target,
                "type": target_type,
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 40,
                        "malicious": 15 if is_malicious else 0,
                        "suspicious": 2 if is_malicious else 0,
                        "undetected": 10,
                        "timeout": 0,
                    },
                    "reputation": -50 if is_malicious else 100,
                }
            }
        }

    # Real lookup
    endpoint_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{target}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{target}",
        "hash": f"https://www.virustotal.com/api/v3/files/{target}",
    }
    url = endpoint_map.get(target_type)
    if not url:
        return {"error": "Unsupported VirusTotal target type"}

    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"not_found": True, "error": "Target not found on VirusTotal"}
            else:
                logger.warning("VirusTotal API returned status code %s", resp.status_code)
                return {"error": f"VirusTotal API error status: {resp.status_code}"}
    except Exception as e:
        logger.error("Error querying VirusTotal API: %s", e)
        return {"error": str(e)}


def check_abuseipdb(ip_address: str) -> Dict[str, Any]:
    """
    Queries AbuseIPDB v2 API for IP reputation.
    Runs in simulation mode if ABUSEIPDB_API_KEY is not set.
    """
    if not settings.ABUSEIPDB_API_KEY:
        # Simulation Mode
        is_malicious = (ip_address.strip() == "1.1.1.1")
        return {
            "data": {
                "ipAddress": ip_address,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": not is_malicious,
                "abuseConfidenceScore": 85 if is_malicious else 0,
                "countryCode": "US",
                "usageType": "Content Delivery Network",
                "isp": "Cloudflare, Inc.",
                "domain": "cloudflare.com",
                "totalReports": 128 if is_malicious else 0,
                "lastReportedAt": datetime.now(timezone.utc).isoformat() if is_malicious else None,
            }
        }

    # Real lookup
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip_address.strip(),
        "maxAgeInDays": "90",
        "verbose": "true"
    }
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    try:
        with httpx.Client(timeout=6.0) as client:
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning("AbuseIPDB API returned status code %s", resp.status_code)
                return {"error": f"AbuseIPDB API error status: {resp.status_code}"}
    except Exception as e:
        logger.error("Error querying AbuseIPDB API: %s", e)
        return {"error": str(e)}


def check_shodan(ip_address: str) -> Dict[str, Any]:
    """
    Queries Shodan Host API for open ports and services banner.
    Runs in simulation mode if SHODAN_API_KEY is not set.
    """
    if not settings.SHODAN_API_KEY:
        # Simulation Mode
        is_cloudflare = (ip_address.strip() == "1.1.1.1")
        return {
            "ip_str": ip_address,
            "ports": [80, 443, 8080] if is_cloudflare else [80, 443],
            "isp": "Cloudflare, Inc." if is_cloudflare else "Generic ISP",
            "hostnames": ["one.one.one.one"] if is_cloudflare else [],
            "org": "Cloudflare, Inc." if is_cloudflare else "Generic Org",
            "country_name": "United States",
            "data": [
                {
                    "port": 80,
                    "transport": "tcp",
                    "info": "HTTP Server Banner Mock",
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "info": "HTTPS Server Banner Mock",
                }
            ]
        }

    # Real lookup
    url = f"https://api.shodan.io/shodan/host/{ip_address.strip()}?key={settings.SHODAN_API_KEY}"

    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"ports": [], "error": "No information found for this host"}
            else:
                logger.warning("Shodan API returned status code %s", resp.status_code)
                return {"error": f"Shodan API error status: {resp.status_code}"}
    except Exception as e:
        logger.error("Error querying Shodan API: %s", e)
        return {"error": str(e)}


def analyze_threat_intel(db: Session, investigation_id: str, raw_target: str) -> Dict[str, Any]:
    """
    Main Threat Intelligence Scanner.
    Detects target type, runs lookup APIs, computes a unified 0-10 reputation score,
    and persists findings and IOC updates in the database.
    """
    clean_target = sanitize_target(raw_target)

    # 1. Determine Target Type
    if validate_ip(clean_target):
        target_type = "ip"
    elif validate_domain(clean_target):
        target_type = "domain"
    elif validate_hash(clean_target):
        target_type = "hash"
    else:
        raise ValueError(f"Invalid target format: '{raw_target}'. Must be a valid IP, Domain, or Hash.")

    logger.info("Starting Threat Intelligence scan for target: %s (%s)", clean_target, target_type)

    vt_data = None
    abuse_data = None
    shodan_data = None

    # 2. Run Scanner Pipelines
    if target_type == "ip":
        vt_data = check_virustotal(clean_target, "ip")
        abuse_data = check_abuseipdb(clean_target)
        shodan_data = check_shodan(clean_target)
    elif target_type == "domain":
        vt_data = check_virustotal(clean_target, "domain")
    elif target_type == "hash":
        vt_data = check_virustotal(clean_target, "hash")

    # 3. Compute Deterministic Threat Level & Unified Safety Score
    vt_malicious = 0
    vt_suspicious = 0
    if vt_data and isinstance(vt_data, dict) and "data" in vt_data:
        attrs = vt_data["data"].get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        vt_malicious = stats.get("malicious", 0)
        vt_suspicious = stats.get("suspicious", 0)

    abuse_confidence = 0
    total_reports = 0
    country_code = "N/A"
    is_whitelisted = False
    if abuse_data and isinstance(abuse_data, dict) and "data" in abuse_data:
        ab_data = abuse_data["data"] or {}
        abuse_confidence = ab_data.get("abuseConfidenceScore", 0)
        total_reports = ab_data.get("totalReports", 0)
        country_code = ab_data.get("countryCode", "N/A")
        is_whitelisted = ab_data.get("isWhitelisted", False)
        # Helper keys for direct frontend access
        abuse_data["abuse_confidence_score"] = abuse_confidence
        abuse_data["total_reports"] = total_reports
        abuse_data["country_code"] = country_code
        abuse_data["is_whitelisted"] = is_whitelisted

    # Dynamic multi-feed safety calculation (100 = clean safe, 0 = critical malware)
    total_malicious_weight = (vt_malicious * 15) + (vt_suspicious * 5) + (abuse_confidence * 0.8)

    if vt_malicious >= 5 or abuse_confidence >= 75 or total_malicious_weight >= 60:
        threat_level = "Critical" if (vt_malicious >= 10 or abuse_confidence >= 90) else "Malicious"
        unified_score = max(0, int(100 - total_malicious_weight))
    elif vt_malicious >= 2 or abuse_confidence >= 25 or total_malicious_weight >= 25:
        threat_level = "Suspicious"
        unified_score = max(20, int(100 - total_malicious_weight))
    elif vt_malicious >= 1 or abuse_confidence > 0 or total_malicious_weight > 0:
        threat_level = "Low"
        unified_score = max(50, int(100 - total_malicious_weight))
    else:
        threat_level = "Clean"
        unified_score = 100

    reputation_score = round(min(10.0, (100 - unified_score) / 10.0), 1)

    finding_id = str(uuid.uuid4())

    # 4. Format scan result payload
    scan_result = {
        "finding_id": finding_id,
        "target": clean_target,
        "target_type": target_type,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "virustotal": vt_data,
        "abuseipdb": abuse_data,
        "shodan": shodan_data,
        "threat_level": threat_level,
        "unified_score": unified_score,
        "reputation_score": reputation_score,
        "simulation_mode": {
            "virustotal": settings.VIRUSTOTAL_API_KEY is None,
            "abuseipdb": settings.ABUSEIPDB_API_KEY is None,
            "shodan": settings.SHODAN_API_KEY is None,
        },
        "summary": {
            "vt_malicious_count": vt_malicious,
            "vt_suspicious_count": vt_suspicious,
            "abuse_confidence": abuse_confidence,
            "threat_level": threat_level,
            "unified_score": unified_score,
            "shodan_ports": shodan_data.get("ports", []) if shodan_data else [],
        }
    }

    # 5. Store finding
    finding = Finding(
        id=finding_id,
        investigation_id=investigation_id,
        module="threat_intel",
        type="threat_scan",
        data=scan_result,
    )
    db.add(finding)

    # 6. Store or Update IOC in database
    ioc = db.query(IOC).filter(IOC.value == clean_target).first()
    if ioc:
        # Update existing IOC details
        ioc.reputation_score = max(ioc.reputation_score, reputation_score)
        ioc.last_seen = datetime.now(timezone.utc)
    else:
        # Register new IOC
        ioc = IOC(
            value=clean_target,
            type=target_type,
            source="threat_intel_module",
            reputation_score=reputation_score,
        )
        db.add(ioc)

    db.commit()
    db.refresh(finding)

    return scan_result
