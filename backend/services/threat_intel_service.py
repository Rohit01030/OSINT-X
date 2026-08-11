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

    # 3. Compute Deterministic Reputation Score (0.0 to 10.0)
    score = 0.0
    
    # VirusTotal score contribution: malicious detection count
    if vt_data and "data" in vt_data and "attributes" in vt_data["data"]:
        stats = vt_data["data"]["attributes"].get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            # Scale up to 10.0: e.g. 5+ engine detections makes it 10.0
            score = max(score, min(10.0, malicious * 2.0))

    # AbuseIPDB score contribution: abuse confidence score
    if abuse_data and "data" in abuse_data:
        confidence = abuse_data["data"].get("abuseConfidenceScore", 0)
        score = max(score, (confidence / 100.0) * 10.0)

    # Round reputation score to 1 decimal place
    reputation_score = round(score, 1)

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
        "reputation_score": reputation_score,
        "simulation_mode": {
            "virustotal": settings.VIRUSTOTAL_API_KEY is None,
            "abuseipdb": settings.ABUSEIPDB_API_KEY is None,
            "shodan": settings.SHODAN_API_KEY is None,
        },
        "summary": {
            "vt_malicious_count": vt_data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0) if (vt_data and "data" in vt_data) else 0,
            "abuse_confidence": abuse_data["data"].get("abuseConfidenceScore", 0) if (abuse_data and "data" in abuse_data) else 0,
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
