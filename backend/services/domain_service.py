"""
Domain Intelligence Service Layer.
Performs WHOIS/RDAP lookups, DNS resolution, SSL/TLS certificate auditing,
HTTP security headers evaluation, technology stack detection, and passive subdomain enumeration.
Stores scan findings into the PostgreSQL/SQLite findings table.
"""
import uuid
import socket
import ssl
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx
import dns.resolver
import dns.reversename
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_domain, sanitize_target

logger = logging.getLogger(__name__)


def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Queries DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) and performs reverse PTR lookups for IPs.
    """
    records: Dict[str, Any] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "CNAME": [],
        "SOA": None,
        "PTR": {},
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    # Query Record Types
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "A":
                records["A"] = [r.address for r in answers]
            elif rtype == "AAAA":
                records["AAAA"] = [r.address for r in answers]
            elif rtype == "MX":
                records["MX"] = [{"preference": r.preference, "exchange": str(r.exchange).rstrip(".")} for r in answers]
            elif rtype == "NS":
                records["NS"] = [str(r.target).rstrip(".") for r in answers]
            elif rtype == "TXT":
                records["TXT"] = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
            elif rtype == "CNAME":
                records["CNAME"] = [str(r.target).rstrip(".") for r in answers]
            elif rtype == "SOA":
                if answers:
                    soa = answers[0]
                    records["SOA"] = {
                        "mname": str(soa.mname).rstrip("."),
                        "rname": str(soa.rname).rstrip("."),
                        "serial": soa.serial,
                    }
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, Exception):
            pass

    # PTR lookups for A records
    for ip in records["A"][:5]:
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answer = resolver.resolve(rev_name, "PTR")
            if ptr_answer:
                records["PTR"][ip] = str(ptr_answer[0].target).rstrip(".")
        except Exception:
            records["PTR"][ip] = None

    return records


def get_ssl_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Connects via TLS socket to audit SSL/TLS certificate details (issuer, subject, SANs, validity dates).
    """
    result: Dict[str, Any] = {
        "valid": False,
        "subject": {},
        "issuer": {},
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "sans": [],
        "serial_number": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, port), timeout=4.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result["valid"] = True
                    result["serial_number"] = cert.get("serialNumber")

                    # Parse Subject
                    for item in cert.get("subject", ()):
                        for key, val in item:
                            result["subject"][key] = val

                    # Parse Issuer
                    for item in cert.get("issuer", ()):
                        for key, val in item:
                            result["issuer"][key] = val

                    # Parse Dates
                    date_format = "%b %d %H:%M:%S %Y %Z"
                    if "notBefore" in cert:
                        dt_from = datetime.strptime(cert["notBefore"], date_format).replace(tzinfo=timezone.utc)
                        result["valid_from"] = dt_from.isoformat()
                    if "notAfter" in cert:
                        dt_to = datetime.strptime(cert["notAfter"], date_format).replace(tzinfo=timezone.utc)
                        result["valid_to"] = dt_to.isoformat()
                        now = datetime.now(timezone.utc)
                        days_left = (dt_to - now).days
                        result["days_remaining"] = days_left

                    # Subject Alternative Names (SANs)
                    sans = []
                    for type_name, name in cert.get("subjectAltName", ()):
                        if type_name == "DNS":
                            sans.append(name)
                    result["sans"] = sans

    except Exception as e:
        logger.warning("SSL audit error for %s: %s", domain, e)
        result["error"] = str(e)

    return result


def get_whois_data(domain: str) -> Dict[str, Any]:
    """
    Fetches WHOIS/RDAP registration data for the target domain.
    """
    whois_info: Dict[str, Any] = {
        "domain_name": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "registrant_country": None,
        "raw": None,
    }

    # Primary RDAP lookup via rdap.org API
    try:
        url = f"https://rdap.org/domain/{domain}"
        with httpx.Client(timeout=4.0, follow_redirects=True) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                whois_info["domain_name"] = data.get("ldhName", domain)

                # Entities (Registrar)
                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    if "registrar" in roles:
                        vcard = entity.get("vcardArray", [])
                        if len(vcard) > 1:
                            for entry in vcard[1]:
                                if entry[0] == "fn":
                                    whois_info["registrar"] = entry[3]

                # Events (Dates)
                for event in data.get("events", []):
                    action = event.get("eventAction")
                    date_str = event.get("eventDate")
                    if action == "registration":
                        whois_info["creation_date"] = date_str
                    elif action == "expiration":
                        whois_info["expiration_date"] = date_str
                    elif action == "last changed":
                        whois_info["updated_date"] = date_str

                # Name Servers
                ns_list = []
                for ns in data.get("nameservers", []):
                    if "ldhName" in ns:
                        ns_list.append(ns["ldhName"])
                whois_info["name_servers"] = ns_list
                whois_info["status"] = data.get("status", [])
                return whois_info
    except Exception as e:
        logger.warning("RDAP lookup failed for %s: %s", domain, e)

    return whois_info


def get_http_headers_and_tech(domain: str) -> Dict[str, Any]:
    """
    Inspects HTTP/HTTPS response headers, security header configuration, and infers technology stack.
    """
    result: Dict[str, Any] = {
        "url_tested": f"https://{domain}",
        "status_code": None,
        "server": None,
        "security_headers": {},
        "security_score": "F",
        "tech_stack": [],
        "raw_headers": {},
        "error": None,
    }

    sec_header_keys = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    try:
        with httpx.Client(timeout=4.0, follow_redirects=True, verify=False) as client:
            resp = client.get(f"https://{domain}")
            result["status_code"] = resp.status_code
            headers = {k.title(): v for k, v in resp.headers.items()}
            result["raw_headers"] = dict(headers)
            result["server"] = headers.get("Server")

            # Check Security Headers
            score_points = 0
            for sec_key in sec_header_keys:
                present = sec_key in headers or sec_key.lower() in [h.lower() for h in headers.keys()]
                val = headers.get(sec_key) or headers.get(sec_key.lower())
                result["security_headers"][sec_key] = {
                    "present": present,
                    "value": val,
                }
                if present:
                    score_points += 1

            # Calculate Security Score
            if score_points >= 6:
                result["security_score"] = "A+"
            elif score_points >= 5:
                result["security_score"] = "A"
            elif score_points >= 4:
                result["security_score"] = "B"
            elif score_points >= 2:
                result["security_score"] = "C"
            elif score_points >= 1:
                result["security_score"] = "D"
            else:
                result["security_score"] = "F"

            # Tech Stack Detection from headers
            tech = set()
            server_val = (headers.get("Server") or "").lower()
            if "nginx" in server_val:
                tech.add("Nginx")
            if "apache" in server_val:
                tech.add("Apache")
            if "cloudflare" in server_val:
                tech.add("Cloudflare CDN")
            if "caddy" in server_val:
                tech.add("Caddy Web Server")
            if "express" in (headers.get("X-Powered-By") or "").lower():
                tech.add("Express.js")
            if "next.js" in (headers.get("X-Powered-By") or "").lower() or "x-nextjs" in [h.lower() for h in headers]:
                tech.add("Next.js")
            if "php" in (headers.get("X-Powered-By") or "").lower():
                tech.add("PHP")

            result["tech_stack"] = list(tech)

    except Exception as e:
        logger.warning("HTTP audit error for %s: %s", domain, e)
        result["error"] = str(e)

    return result


def get_subdomains(domain: str) -> List[Dict[str, Any]]:
    """
    Enumerates subdomains using Certificate Transparency (crt.sh) logs.
    """
    subdomains_set = set()
    results = []

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries[:50]:  # Limit to 50 results
                    name = entry.get("name_value")
                    if name:
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{domain}") and not sub.startswith("*"):
                                subdomains_set.add(sub)
    except Exception as e:
        logger.warning("Subdomain enum error for %s: %s", domain, e)

    # Convert to structured list with fallback DNS check
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.5
    for sub in sorted(list(subdomains_set))[:20]:
        resolved_ip = None
        try:
            ans = resolver.resolve(sub, "A")
            if ans:
                resolved_ip = ans[0].address
        except Exception:
            pass

        results.append({
            "subdomain": sub,
            "ip": resolved_ip,
        })

    return results


def analyze_domain(db: Session, investigation_id: str, raw_target: str) -> Dict[str, Any]:
    """
    Main Domain Intelligence Scanner.
    Executes full reconnaissance pipeline and persists structured output in findings table.
    """
    clean_domain = sanitize_target(raw_target)
    if not validate_domain(clean_domain):
        raise ValueError(f"Invalid domain target format: '{raw_target}'")

    logger.info("Starting domain intelligence scan for target: %s", clean_domain)

    # 1. Execute Scanner Pipeline
    dns_data = get_dns_records(clean_domain)
    ssl_data = get_ssl_certificate(clean_domain)
    whois_data = get_whois_data(clean_domain)
    http_data = get_http_headers_and_tech(clean_domain)
    subdomains_data = get_subdomains(clean_domain)

    finding_id = str(uuid.uuid4())

    # 2. Build Finding Data Payload
    scan_result = {
        "finding_id": finding_id,
        "target": clean_domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "whois": whois_data,
        "dns": dns_data,
        "ssl": ssl_data,
        "http": http_data,
        "subdomains": subdomains_data,
        "summary": {
            "a_records_count": len(dns_data.get("A", [])),
            "mx_records_count": len(dns_data.get("MX", [])),
            "subdomains_found": len(subdomains_data),
            "ssl_valid": ssl_data.get("valid", False),
            "security_score": http_data.get("security_score", "F"),
        },
    }

    # 3. Store Finding in DB
    finding = Finding(
        id=finding_id,
        investigation_id=investigation_id,
        module="domain",
        type="domain_scan",
        data=scan_result,
    )
    db.add(finding)

    # 4. Store IOCs in DB (Domain & Resolved IP addresses)
    ioc_domain = db.query(IOC).filter(IOC.value == clean_domain).first()
    if not ioc_domain:
        db.add(IOC(value=clean_domain, type="domain", source="domain_module", reputation_score=0.0))

    for ip in dns_data.get("A", []):
        ioc_ip = db.query(IOC).filter(IOC.value == ip).first()
        if not ioc_ip:
            db.add(IOC(value=ip, type="ip", source="domain_module", reputation_score=0.0))

    db.commit()
    db.refresh(finding)

    return scan_result
