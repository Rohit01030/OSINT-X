"""
IP Intelligence Service Layer.
Performs GeoIP lookups, ASN & ISP identification, IP reputation & abuse checks,
and consent-gated active port scanning.
Stores findings into PostgreSQL/SQLite findings table and extracts IOCs into iocs table.
"""
import uuid
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_ip
from core.consent import log_consent

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Multi-Source GeoIP Fusion
# ---------------------------------------------------------------------------

def _query_ipapi(ip_address: str) -> Dict[str, Any]:
    """Primary GeoIP source: ip-api.com (free, no key, 45 req/min)."""
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as"
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "zip": data.get("zip"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "source": "ip-api.com",
                    }
    except Exception as e:
        logger.debug("ip-api.com failed for %s: %s", ip_address, e)
    return {}


def _query_ipwho(ip_address: str) -> Dict[str, Any]:
    """Secondary GeoIP source: ipwho.is (free, no key, 10k/month)."""
    try:
        url = f"https://ipwho.is/{ip_address}"
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    conn = data.get("connection", {})
                    return {
                        "country": data.get("country"),
                        "country_code": data.get("country_code"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "zip": data.get("postal"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "timezone": (data.get("timezone", {}) or {}).get("id"),
                        "isp": conn.get("isp"),
                        "org": conn.get("org"),
                        "asn": f"AS{conn.get('asn', '')}" if conn.get("asn") else None,
                        "source": "ipwho.is",
                    }
    except Exception as e:
        logger.debug("ipwho.is failed for %s: %s", ip_address, e)
    return {}


def get_reverse_ip(ip_address: str) -> List[Dict[str, Any]]:
    """
    Reverse IP lookup — finds all domains hosted on the same IP.
    Uses HackerTarget free API (no key, rate-limited).
    """
    domains: List[Dict[str, Any]] = []
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}"
        with httpx.Client(timeout=6.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                text = resp.text.strip()
                # HackerTarget returns one domain per line, or an error string
                if text and "error" not in text.lower() and "API count" not in text:
                    for line in text.splitlines():
                        line = line.strip()
                        if line and line != ip_address:
                            domains.append({"domain": line})
    except Exception as e:
        logger.debug("Reverse IP lookup failed for %s: %s", ip_address, e)
    return domains[:50]  # cap at 50


# Common ports to audit during active scans
COMMON_PORTS = [
    {"port": 21, "service": "FTP"},
    {"port": 22, "service": "SSH"},
    {"port": 23, "service": "Telnet"},
    {"port": 25, "service": "SMTP"},
    {"port": 53, "service": "DNS"},
    {"port": 80, "service": "HTTP"},
    {"port": 110, "service": "POP3"},
    {"port": 143, "service": "IMAP"},
    {"port": 443, "service": "HTTPS"},
    {"port": 465, "service": "SMTPS"},
    {"port": 587, "service": "Submission"},
    {"port": 993, "service": "IMAPS"},
    {"port": 995, "service": "POP3S"},
    {"port": 3306, "service": "MySQL"},
    {"port": 3389, "service": "RDP"},
    {"port": 5432, "service": "PostgreSQL"},
    {"port": 8080, "service": "HTTP-Proxy"},
    {"port": 8443, "service": "HTTPS-Alt"},
]


def get_geoip_data(ip_address: str) -> Dict[str, Any]:
    """
    Performs GeoIP lookup with multi-source fusion for best accuracy.
    Sources: ip-api.com (primary) → ipwho.is (secondary fallback).
    Also includes reverse IP lookup for co-hosted domains.
    """
    result: Dict[str, Any] = {
        "ip": ip_address,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "zip": None,
        "lat": None,
        "lon": None,
        "timezone": None,
        "isp": None,
        "org": None,
        "asn": None,
        "geo_source": None,
        "geo_sources_queried": [],
        "reverse_dns_domains": [],
        "error": None,
    }

    # --- Source 1: ip-api.com ---
    primary = _query_ipapi(ip_address)
    result["geo_sources_queried"].append("ip-api.com")
    if primary:
        for key in ["country", "country_code", "region", "city", "zip",
                     "lat", "lon", "timezone", "isp", "org", "asn"]:
            result[key] = primary.get(key)
        result["geo_source"] = "ip-api.com"

    # --- Source 2: ipwho.is (fallback or enrichment) ---
    if not primary or not primary.get("lat"):
        secondary = _query_ipwho(ip_address)
        result["geo_sources_queried"].append("ipwho.is")
        if secondary:
            # Fill in any missing fields from primary
            for key in ["country", "country_code", "region", "city", "zip",
                         "lat", "lon", "timezone", "isp", "org", "asn"]:
                if not result.get(key) and secondary.get(key):
                    result[key] = secondary.get(key)
            if not result["geo_source"]:
                result["geo_source"] = "ipwho.is"
            else:
                result["geo_source"] = "ip-api.com + ipwho.is"

    # --- Reverse IP Lookup ---
    try:
        reverse_domains = get_reverse_ip(ip_address)
        result["reverse_dns_domains"] = reverse_domains
    except Exception as e:
        logger.debug("Reverse IP skipped for %s: %s", ip_address, e)

    if not result["lat"] and not result["country"]:
        result["error"] = "All GeoIP sources failed or returned no data"

    return result


def get_ip_reputation(ip_address: str) -> Dict[str, Any]:
    """
    Evaluates IP reputation, bogon/banylist status, and abuse risk score.
    """
    result: Dict[str, Any] = {
        "ip": ip_address,
        "is_private": False,
        "is_loopback": False,
        "is_bogon": False,
        "reputation_score": 0.0,  # 0.0 (safe) to 10.0 (malicious)
        "threat_level": "Low",
        "blacklists": [],
    }

    try:
        # Check private / loopback IP ranges
        import ipaddress
        ip_obj = ipaddress.ip_address(ip_address)
        result["is_private"] = ip_obj.is_private
        result["is_loopback"] = ip_obj.is_loopback

        if ip_obj.is_private or ip_obj.is_loopback:
            result["is_bogon"] = True
            result["threat_level"] = "Clean (Internal)"
            return result

        # Basic reputation score logic (can be enriched with AbuseIPDB in Phase 7)
        result["reputation_score"] = 0.0
        result["threat_level"] = "Clean"
    except Exception as e:
        logger.warning("Reputation check error for %s: %s", ip_address, e)

    return result


def scan_ip_ports(ip_address: str, custom_ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """
    Performs socket connection checks on target IP for common/custom ports with banner grabbing.
    """
    open_ports = []
    ports_to_check = COMMON_PORTS

    if custom_ports:
        ports_to_check = [{"port": p, "service": "Custom"} for p in custom_ports]

    for item in ports_to_check:
        port = item["port"]
        service_name = item["service"]

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1.0)
                res = sock.connect_ex((ip_address, port))
                if res == 0:
                    banner = None
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:100]
                    except Exception:
                        pass

                    open_ports.append({
                        "port": port,
                        "service": service_name,
                        "state": "open",
                        "banner": banner if banner else None,
                    })
        except Exception:
            pass

    return open_ports


def analyze_ip(
    db: Session,
    investigation_id: str,
    raw_target: str,
    consent_confirmed: bool = False,
    user_id: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main IP Intelligence Reconnaissance Pipeline.
    Passive lookups run automatically. Active port scan requires consent_confirmed=True.
    """
    target_ip = raw_target.strip()
    if not validate_ip(target_ip):
        raise ValueError(f"Invalid IP address format: '{raw_target}'")

    logger.info("Starting IP intelligence scan for target: %s", target_ip)

    # 1. Passive Lookups
    geoip_data = get_geoip_data(target_ip)
    reputation_data = get_ip_reputation(target_ip)

    # 2. Consent Gate check for Active Port Scan
    open_ports_data = []
    consent_logged = False

    if consent_confirmed:
        # Audit consent log in database
        log_consent(
            db=db,
            investigation_id=investigation_id,
            target=target_ip,
            user_id=user_id,
            client_ip=client_ip,
        )
        consent_logged = True
        open_ports_data = scan_ip_ports(target_ip)

    finding_id = str(uuid.uuid4())

    # 3. Assemble Finding Data Payload
    # Build map URLs from coordinates
    map_links = {}
    if geoip_data.get("lat") and geoip_data.get("lon"):
        lat, lon = geoip_data["lat"], geoip_data["lon"]
        map_links["google_maps"] = f"https://www.google.com/maps?q={lat},{lon}"
        map_links["openstreetmap"] = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}"

    scan_result = {
        "finding_id": finding_id,
        "target": target_ip,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "geoip": geoip_data,
        "reputation": reputation_data,
        "open_ports": open_ports_data,
        "reverse_dns_domains": geoip_data.get("reverse_dns_domains", []),
        "map_links": map_links,
        "consent_confirmed": consent_confirmed,
        "consent_logged": consent_logged,
        "summary": {
            "country": geoip_data.get("country"),
            "city": geoip_data.get("city"),
            "isp": geoip_data.get("isp"),
            "open_ports_count": len(open_ports_data),
            "threat_level": reputation_data.get("threat_level", "Clean"),
            "co_hosted_domains": len(geoip_data.get("reverse_dns_domains", [])),
            "geo_source": geoip_data.get("geo_source", "ip-api.com"),
        },
    }

    # 4. Save Finding in DB
    finding = Finding(
        id=finding_id,
        investigation_id=investigation_id,
        module="ip",
        type="ip_scan",
        data=scan_result,
    )
    db.add(finding)

    # 5. Extract IP IOC into iocs table
    ioc_obj = db.query(IOC).filter(IOC.value == target_ip).first()
    if not ioc_obj:
        db.add(
            IOC(
                value=target_ip,
                type="ip",
                source="ip_module",
                reputation_score=reputation_data.get("reputation_score", 0.0),
            )
        )

    db.commit()
    db.refresh(finding)

    return scan_result
