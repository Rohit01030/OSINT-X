"""
OSINT-X Finding Deduplication & Aggregation Service.

Identifies repeated observations across scans, generates deterministic fingerprints,
and merges duplicate findings without losing historical evidence, source attribution,
or first-seen / last-seen timestamps.
"""
import hashlib
import json
import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def generate_finding_fingerprint(module: str, finding_type: str, indicator: str) -> str:
    """
    Creates a deterministic SHA-256 fingerprint representing a unique technical finding.
    Normalizes the indicator to prevent case or trailing slash mismatches.
    """
    norm_indicator = (indicator or "").strip().lower().rstrip("/")
    raw_str = f"{module.strip().lower()}:{finding_type.strip().lower()}:{norm_indicator}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:16]


def deduplicate_investigation_findings(raw_findings: List[Any]) -> Dict[str, Any]:
    """
    Processes all raw database findings for an investigation.
    Merges duplicate observations by fingerprint, preserving:
      - All raw observation IDs
      - Earliest created_at (first_seen) and latest created_at (last_seen)
      - Merged sources and technical evidence
      - Individual severity and confidence ratings
    """
    if not raw_findings:
        return {
            "total_raw_observations": 0,
            "total_unique_findings": 0,
            "duplicate_observations_count": 0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "unique_findings": [],
        }

    unique_map: Dict[str, Dict[str, Any]] = {}
    total_raw = len(raw_findings)

    for item in raw_findings:
        f_id = getattr(item, "id", None) or "raw-obs"
        module = getattr(item, "module", "generic") or "generic"
        f_type = getattr(item, "type", "scan") or "scan"
        data = getattr(item, "data", {}) or {}
        if not isinstance(data, dict):
            data = {}

        created_at = getattr(item, "created_at", None)
        if isinstance(created_at, datetime):
            created_iso = created_at.isoformat()
            created_dt = created_at
        elif isinstance(created_at, str):
            created_iso = created_at
            try:
                created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            except Exception:
                created_dt = datetime.now(timezone.utc)
        else:
            created_iso = datetime.now(timezone.utc).isoformat()
            created_dt = datetime.now(timezone.utc)

        # Extract indicator and human-readable description
        indicator = data.get("target") or data.get("domain") or data.get("ip") or "N/A"
        fp = generate_finding_fingerprint(module, f_type, str(indicator))

        # Determine severity & confidence for this individual finding
        severity, confidence, description, remediation = _analyze_finding_attributes(module, f_type, data)

        if fp not in unique_map:
            unique_map[fp] = {
                "fingerprint": fp,
                "module": module,
                "type": f_type,
                "indicator": str(indicator),
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "remediation": remediation,
                "observation_count": 1,
                "observation_ids": [f_id],
                "first_seen": created_iso,
                "first_seen_dt": created_dt,
                "last_seen": created_iso,
                "last_seen_dt": created_dt,
                "sources": [module],
                "data": data,
                "status": "DETECTED",
            }
        else:
            # Merge duplicate
            entry = unique_map[fp]
            entry["observation_count"] += 1
            if f_id not in entry["observation_ids"]:
                entry["observation_ids"].append(f_id)

            if module not in entry["sources"]:
                entry["sources"].append(module)

            # Update first_seen / last_seen timestamps
            if created_dt < entry["first_seen_dt"]:
                entry["first_seen_dt"] = created_dt
                entry["first_seen"] = created_iso
            if created_dt > entry["last_seen_dt"]:
                entry["last_seen_dt"] = created_dt
                entry["last_seen"] = created_iso
                # Keep latest telemetry data
                entry["data"] = data

            # Upgrade severity if a subsequent observation revealed higher risk
            entry["severity"] = _pick_higher_severity(entry["severity"], severity)
            entry["confidence"] = _pick_higher_confidence(entry["confidence"], confidence)

    unique_list = list(unique_map.values())

    # Sort: highest severity first, then by last_seen
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    unique_list.sort(key=lambda x: (sev_rank.get(x["severity"], 5), -x["last_seen_dt"].timestamp()))

    # Clean temporary datetime objects
    sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for item in unique_list:
        item.pop("first_seen_dt", None)
        item.pop("last_seen_dt", None)
        s = item["severity"]
        if s in sev_dist:
            sev_dist[s] += 1

    total_unique = len(unique_list)
    duplicate_count = total_raw - total_unique

    return {
        "total_raw_observations": total_raw,
        "total_unique_findings": total_unique,
        "duplicate_observations_count": duplicate_count,
        "severity_distribution": sev_dist,
        "unique_findings": unique_list,
    }


def _analyze_finding_attributes(module: str, f_type: str, data: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Inspects finding data payload to classify severity, confidence, description, and remediation."""
    if module == "threat_intel":
        vt = data.get("virustotal", {})
        vt_attrs = ((vt.get("data") or {}).get("attributes") or {}) if isinstance(vt, dict) else {}
        vt_malicious = ((vt_attrs.get("last_analysis_stats") or {}).get("malicious", 0)) if isinstance(vt_attrs, dict) else 0

        abuse = data.get("abuseipdb", {})
        abuse_conf = ((abuse.get("data") or {}).get("abuseConfidenceScore", 0)) if isinstance(abuse, dict) else 0

        if vt_malicious >= 5 or abuse_conf >= 75:
            return (
                "CRITICAL",
                "CONFIRMED",
                f"Indicator confirmed malicious by {vt_malicious} VirusTotal engines and AbuseIPDB ({abuse_conf}% confidence).",
                "Immediately blacklist indicator across firewalls and SIEM correlation rules.",
            )
        elif vt_malicious >= 2 or abuse_conf >= 25:
            return (
                "HIGH",
                "HIGH",
                f"Elevated threat reputation: {vt_malicious} VT detections, AbuseIPDB confidence score {abuse_conf}%.",
                "Restrict traffic to this indicator and monitor internal host connections.",
            )
        else:
            return (
                "LOW",
                "MEDIUM",
                "Threat intelligence audit complete; no widespread malicious reputation reported.",
                "Continue standard threat feed monitoring.",
            )

    elif module == "ip":
        raw_ports = data.get("open_ports", [])
        ports = []
        if isinstance(raw_ports, list):
            for p in raw_ports:
                try:
                    if isinstance(p, dict):
                        p_num = int(p.get("port") or p.get("number") or 0)
                    else:
                        p_num = int(p)
                    if p_num > 0:
                        ports.append(p_num)
                except (ValueError, TypeError):
                    continue

        from services.risk_engine import HIGH_RISK_PORTS
        has_critical = any(p in [23, 445, 1433, 3389, 27017, 6379] for p in ports)
        has_risky = any(p in HIGH_RISK_PORTS for p in ports)

        if has_critical:
            return (
                "HIGH",
                "CONFIRMED",
                f"Critical administrative services exposed on public IP: {ports}.",
                "Place administrative ports behind a VPN or firewall whitelist.",
            )
        elif has_risky:
            return (
                "MEDIUM",
                "CONFIRMED",
                f"High-risk network ports listening on host: {ports}.",
                "Audit listening services and restrict unnecessary perimeter access.",
            )
        elif ports:
            return (
                "INFO",
                "CONFIRMED",
                f"Standard service ports active on host: {ports}.",
                "Ensure TLS is enforced and services are patched to current versions.",
            )
        else:
            return (
                "INFO",
                "CONFIRMED",
                "IP intelligence audit completed; no open ports discovered.",
                "Maintain periodic port exposure audits.",
            )

    elif module == "email":
        raw_breaches = data.get("breaches", {})
        count = raw_breaches.get("total_breaches", 0) if isinstance(raw_breaches, dict) else (len(raw_breaches) if isinstance(raw_breaches, list) else 0)
        is_disp = data.get("is_disposable", False)

        if count >= 3:
            return (
                "HIGH",
                "CONFIRMED",
                f"Email account identified in {count} known public data breaches.",
                "Enforce immediate credential reset and multi-factor authentication.",
            )
        elif count >= 1 or is_disp:
            return (
                "MEDIUM",
                "CONFIRMED",
                f"Email found in {count} data breach incident(s) or operates as a disposable mailbox.",
                "Verify user identity and review account security settings.",
            )
        else:
            return (
                "INFO",
                "CONFIRMED",
                "Email address verified with clean public breach reputation.",
                "Continue standard credential hygiene practices.",
            )

    elif module == "domain":
        ssl_data = data.get("ssl", {})
        ssl_valid = ssl_data.get("valid", True) if isinstance(ssl_data, dict) else True
        http_data = data.get("http", {})
        sec_score = http_data.get("security_score", "A") if isinstance(http_data, dict) else "A"

        if not ssl_valid and ssl_data:
            return (
                "HIGH",
                "CONFIRMED",
                "Domain TLS certificate is invalid, self-signed, or expired.",
                "Renew TLS certificate via an automated ACME provider.",
            )
        elif sec_score in ["F", "D"]:
            return (
                "LOW",
                "HIGH",
                f"HTTP response headers have poor hardening rating ({sec_score}).",
                "Implement standard security headers: CSP, HSTS, and X-Frame-Options.",
            )
        else:
            return (
                "INFO",
                "HIGH",
                "Domain resolution and web infrastructure audit completed.",
                "Maintain periodic domain configuration reviews.",
            )

    elif module == "username":
        summary = data.get("summary", {})
        found = summary.get("total_found", 0) if isinstance(summary, dict) else 0
        if found >= 8:
            return (
                "INFO",
                "HIGH",
                f"Username identity active across {found} public online platforms.",
                "Review personal information exposure on public profiles.",
            )
        else:
            return (
                "INFO",
                "HIGH",
                f"Username enumerated across social and developer platforms ({found} matches).",
                "Informational account enumeration.",
            )

    elif module == "file":
        return (
            "INFO",
            "CONFIRMED",
            "Cryptographic hashes and image metadata calculated for file artifact.",
            "Verify file hash against external threat repositories.",
        )

    return ("INFO", "LOW", "General OSINT observation recorded.", "No action required.")


def _pick_higher_severity(s1: str, s2: str) -> str:
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return s1 if rank.get(s1, 5) <= rank.get(s2, 5) else s2


def _pick_higher_confidence(c1: str, c2: str) -> str:
    rank = {"CONFIRMED": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return c1 if rank.get(c1, 4) <= rank.get(c2, 4) else c2
