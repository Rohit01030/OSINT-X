"""
OSINT-X Risk Assessment & Threat Scoring Engine.

Implements an evidence-based, transparent, and deterministic risk-scoring methodology.
Differentiates between:
  - Technical Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Analytical Confidence (CONFIRMED, HIGH, MEDIUM, LOW)
  - Organizational Risk (CRITICAL, HIGH, ELEVATED, LOW, NEGLIGIBLE, INCONCLUSIVE)

Key Principles:
  1. Open ports are NOT automatically vulnerabilities (standard ports 80/443 are informational).
     Only high-risk administrative or unencrypted management ports contribute risk points.
  2. Missing security headers are configuration weaknesses, NOT critical vulnerabilities (max +0.8).
  3. Threat intelligence engines (VirusTotal, AbuseIPDB) are validated against verified indicators.
  4. Multiple neutral or informational findings never compound into a critical risk score.
  5. When findings are empty or targets have no telemetry, the assessment is explicitly INCONCLUSIVE.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Sensitive / High-Risk Port Definitions (Port: Description, Weight)
HIGH_RISK_PORTS = {
    21: ("FTP (Unencrypted File Transfer)", 0.8, "HIGH"),
    23: ("Telnet (Cleartext Remote Shell)", 1.2, "CRITICAL"),
    25: ("SMTP (Unauthenticated Mail Relay Risk)", 0.4, "LOW"),
    69: ("TFTP (Trivial FTP without Authentication)", 0.9, "HIGH"),
    110: ("POP3 (Unencrypted Mail Delivery)", 0.4, "LOW"),
    135: ("RPC / Endpoint Mapper", 0.7, "MEDIUM"),
    139: ("NetBIOS Session Service", 0.8, "MEDIUM"),
    445: ("SMB (Direct-hosted NetBIOS / Ransomware vector)", 1.2, "HIGH"),
    1433: ("Microsoft SQL Server Exposed", 1.0, "HIGH"),
    1521: ("Oracle Database Listener Exposed", 1.0, "HIGH"),
    3306: ("MySQL Database Exposed", 0.8, "MEDIUM"),
    3389: ("RDP (Remote Desktop Protocol Exposed)", 1.1, "HIGH"),
    5432: ("PostgreSQL Database Exposed", 0.8, "MEDIUM"),
    5900: ("VNC (Virtual Network Computing Exposed)", 1.0, "HIGH"),
    6379: ("Redis (Exposed In-Memory Data Store)", 1.2, "HIGH"),
    9200: ("Elasticsearch REST API Exposed", 1.0, "HIGH"),
    27017: ("MongoDB Exposed", 1.2, "HIGH"),
}

STANDARD_PORTS = {80, 443, 8080, 8443, 53, 123}


class ScoringFactor:
    """Represents a single transparent, quantifiable risk contribution factor."""
    def __init__(
        self,
        name: str,
        module: str,
        indicator: str,
        raw_metric: str,
        weight: float,
        contribution: float,
        severity: str,
        confidence: str,
        evidence: str,
        remediation: str,
    ):
        self.name = name
        self.module = module
        self.indicator = indicator
        self.raw_metric = raw_metric
        self.weight = weight
        self.contribution = round(contribution, 2)
        self.severity = severity
        self.confidence = confidence
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "module": self.module,
            "indicator": self.indicator,
            "raw_metric": self.raw_metric,
            "weight": self.weight,
            "contribution": self.contribution,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


def assess_investigation_risk(findings: List[Any], target_context: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluates all investigation findings deterministically.
    Produces comprehensive risk score, breakdown of factors, severity distributions, and confidence rating.
    """
    factors: List[ScoringFactor] = []
    total_score = 0.0

    if not findings:
        return {
            "risk_score": 0.0,
            "risk_level": "SAFE",
            "organizational_impact": "NEGLIGIBLE",
            "confidence": "LOW",
            "status": "INSUFFICIENT_EVIDENCE",
            "inconclusive": True,
            "scoring_factors": [],
            "summary_statement": "No investigation findings have been recorded. Assessment has insufficient evidence.",
            "factors_count": 0,
            "max_severity": "INFO",
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "confidence_distribution": {"CONFIRMED": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        }

    for f in findings:
        module = getattr(f, "module", "") or ""
        f_type = getattr(f, "type", "") or ""
        data = getattr(f, "data", {}) or {}
        if not isinstance(data, dict):
            continue

        target = data.get("target") or target_context or "Target"

        # ------------------------------------------------------------------
        # 1. THREAT INTEL: VirusTotal & AbuseIPDB
        # ------------------------------------------------------------------
        if module == "threat_intel":
            # VirusTotal validation
            vt = data.get("virustotal") or {}
            vt_data = vt.get("data") if isinstance(vt, dict) else {}
            vt_attrs = vt_data.get("attributes") if isinstance(vt_data, dict) else {}
            last_stats = vt_attrs.get("last_analysis_stats") if isinstance(vt_attrs, dict) else {}
            malicious = last_stats.get("malicious", 0) if isinstance(last_stats, dict) else 0
            suspicious = last_stats.get("suspicious", 0) if isinstance(last_stats, dict) else 0

            if malicious >= 5:
                # Confirmed malicious activity across multiple engines
                inc = min(4.0, 2.0 + (malicious - 5) * 0.15)
                factors.append(
                    ScoringFactor(
                        name="Confirmed Malicious Indicator (Multi-Engine)",
                        module="threat_intel",
                        indicator=str(target),
                        raw_metric=f"{malicious} VT AV engines detected malware",
                        weight=4.0,
                        contribution=inc,
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        evidence=f"VirusTotal telemetry confirmed malicious detections across {malicious} independent security vendors.",
                        remediation="Block indicator at firewall/EDR edge and isolate any internal systems communicating with it.",
                    )
                )
                total_score += inc
            elif malicious >= 2:
                # Moderate threat detection
                inc = 1.5 + (malicious * 0.2)
                factors.append(
                    ScoringFactor(
                        name="Elevated Threat Intel Flag (VirusTotal)",
                        module="threat_intel",
                        indicator=str(target),
                        raw_metric=f"{malicious} VT engines detected threat",
                        weight=2.5,
                        contribution=inc,
                        severity="HIGH",
                        confidence="HIGH",
                        evidence=f"Flagged by {malicious} VirusTotal security vendors.",
                        remediation="Investigate host traffic logs and apply conditional block or heightened monitoring.",
                    )
                )
                total_score += inc
            elif malicious == 1 or suspicious >= 2:
                # Low-confidence heuristic detection (avoid false positive escalation)
                inc = 0.5
                factors.append(
                    ScoringFactor(
                        name="Low-Confidence Security Vendor Flag",
                        module="threat_intel",
                        indicator=str(target),
                        raw_metric=f"{malicious} malicious / {suspicious} suspicious vendor(s)",
                        weight=1.0,
                        contribution=inc,
                        severity="LOW",
                        confidence="MEDIUM",
                        evidence="Single engine detection or heuristic flag. May be a false positive or emerging indicator.",
                        remediation="Perform secondary reputation verification before enacting blocking actions.",
                    )
                )
                total_score += inc

            # AbuseIPDB validation
            abuse = data.get("abuseipdb") or {}
            abuse_data = abuse.get("data") if isinstance(abuse, dict) else {}
            abuse_conf = abuse_data.get("abuseConfidenceScore", 0) if isinstance(abuse_data, dict) else 0
            total_reports = abuse_data.get("totalReports", 0) if isinstance(abuse_data, dict) else 0

            if abuse_conf >= 50:
                inc = min(3.0, (abuse_conf / 100.0) * 3.0)
                factors.append(
                    ScoringFactor(
                        name="High-Confidence Abuse & Attack History",
                        module="threat_intel",
                        indicator=str(target),
                        raw_metric=f"AbuseIPDB Confidence: {abuse_conf}%, Reports: {total_reports}",
                        weight=3.0,
                        contribution=inc,
                        severity="HIGH",
                        confidence="HIGH",
                        evidence=f"Crowdsourced SOC abuse reports verify malicious activity ({abuse_conf}% confidence, {total_reports} reports).",
                        remediation="Implement IP rate limiting or perimeter ACL deny rule for inbound traffic.",
                    )
                )
                total_score += inc
            elif abuse_conf >= 25:
                inc = 1.0
                factors.append(
                    ScoringFactor(
                        name="Moderate Abuse Reputation Flag",
                        module="threat_intel",
                        indicator=str(target),
                        raw_metric=f"AbuseIPDB Confidence: {abuse_conf}%, Reports: {total_reports}",
                        weight=1.5,
                        contribution=inc,
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        evidence=f"Moderate abuse confidence ({abuse_conf}%) reported across threat feeds.",
                        remediation="Review network ingress/egress connections against this IP.",
                    )
                )
                total_score += inc

        # ------------------------------------------------------------------
        # 2. IP MODULE: Exposed Port Analysis (Differentiated)
        # ------------------------------------------------------------------
        elif module == "ip":
            ports = data.get("open_ports", [])
            if isinstance(ports, list) and ports:
                # Categorize ports
                risky_found = []
                standard_found = []
                other_found = []

                for p in ports:
                    try:
                        p_int = int(p.get("port") if isinstance(p, dict) else p)
                    except (ValueError, TypeError):
                        continue

                    if p_int in HIGH_RISK_PORTS:
                        desc, weight, sev = HIGH_RISK_PORTS[p_int]
                        risky_found.append((p_int, desc, weight, sev))
                    elif p_int in STANDARD_PORTS:
                        standard_found.append(p_int)
                    else:
                        other_found.append(p_int)

                # Process high-risk administrative ports
                for p_num, desc, weight, sev in risky_found:
                    inc = weight
                    factors.append(
                        ScoringFactor(
                            name=f"High-Risk Exposed Port {p_num}",
                            module="ip",
                            indicator=str(target),
                            raw_metric=f"Port {p_num} ({desc}) open to public Internet",
                            weight=weight,
                            contribution=inc,
                            severity=sev,
                            confidence="CONFIRMED",
                            evidence=f"Host responds to active socket probes on port {p_num} ({desc}).",
                            remediation=f"Restrict access to port {p_num} using firewall rules, VPN gateway, or bind to localhost only.",
                        )
                    )
                    total_score += inc

                # Non-standard unknown ports (evaluated moderately)
                if other_found and not risky_found:
                    inc = min(0.6, len(other_found) * 0.2)
                    factors.append(
                        ScoringFactor(
                            name="Non-Standard Ports Exposed",
                            module="ip",
                            indicator=str(target),
                            raw_metric=f"Open ports: {other_found[:4]}",
                            weight=0.6,
                            contribution=inc,
                            severity="LOW",
                            confidence="HIGH",
                            evidence=f"Discovered {len(other_found)} open non-standard port(s): {other_found[:6]}.",
                            remediation="Audit listening daemon services and terminate unnecessary background network listeners.",
                        )
                    )
                    total_score += inc

        # ------------------------------------------------------------------
        # 3. EMAIL MODULE: Breaches, Disposable & Mail Spoofing
        # ------------------------------------------------------------------
        elif module == "email":
            # Breaches check
            raw_breaches = data.get("breaches", {})
            if isinstance(raw_breaches, dict):
                breach_count = raw_breaches.get("total_breaches", 0)
                breach_names = raw_breaches.get("breach_names", [])
            elif isinstance(raw_breaches, list):
                breach_count = len(raw_breaches)
                breach_names = [b.get("Name") or b.get("Title") for b in raw_breaches if isinstance(b, dict)]
            else:
                breach_count = 0
                breach_names = []

            if breach_count >= 3:
                inc = round(min(3.0, breach_count * 1.0), 1)
                factors.append(
                    ScoringFactor(
                        name="Multiple Credential Breach Involvements",
                        module="email",
                        indicator=str(target),
                        raw_metric=f"{breach_count} confirmed breach occurrences",
                        weight=3.0,
                        contribution=inc,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        evidence=f"Identity identified in public breach repositories ({', '.join(breach_names[:4])}). High credential stuffing risk.",
                        remediation="Enforce mandatory password reset and require FIDO2 / TOTP multi-factor authentication.",
                    )
                )
                total_score += inc
            elif breach_count >= 1:
                inc = 1.0
                factors.append(
                    ScoringFactor(
                        name="Identified in Known Data Breach",
                        module="email",
                        indicator=str(target),
                        raw_metric=f"{breach_count} breach occurrence: {', '.join(breach_names[:2])}",
                        weight=1.0,
                        contribution=inc,
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        evidence=f"Found in {breach_count} security incident repository ({', '.join(breach_names[:2])}).",
                        remediation="Verify password uniqueness and check if breached passwords are reused elsewhere.",
                    )
                )
                total_score += inc

            # Disposable email check
            if data.get("is_disposable"):
                inc = 1.0
                factors.append(
                    ScoringFactor(
                        name="Disposable / Burner Mailbox Detected",
                        module="email",
                        indicator=str(target),
                        raw_metric="Domain matches known temporary mailbox provider",
                        weight=1.0,
                        contribution=inc,
                        severity="MEDIUM",
                        confidence="CONFIRMED",
                        evidence="Target domain is operated by a disposable email relay, commonly used for fraud or evasion.",
                        remediation="Flag account for identity verification or block disposable domain registrations.",
                    )
                )
                total_score += inc

            # DNS Email Security Posture (SPF & DMARC)
            dns_sec = data.get("dns_security") or data.get("email_security") or {}
            has_spf = dns_sec.get("has_spf") if isinstance(dns_sec, dict) else bool(dns_sec.get("spf"))
            has_dmarc = dns_sec.get("has_dmarc") if isinstance(dns_sec, dict) else bool(dns_sec.get("dmarc"))

            if not has_spf or not has_dmarc:
                missing = []
                if not has_spf:
                    missing.append("SPF")
                if not has_dmarc:
                    missing.append("DMARC")

                inc = round(0.5 * len(missing), 1)
                factors.append(
                    ScoringFactor(
                        name="Email Spoofing Vulnerability (Missing Authentication Records)",
                        module="email",
                        indicator=str(target),
                        raw_metric=f"Missing: {', '.join(missing)}",
                        weight=1.0,
                        contribution=inc,
                        severity="LOW",
                        confidence="HIGH",
                        evidence=f"Domain lacks published {', '.join(missing)} TXT records, allowing unauthenticated attackers to spoof emails.",
                        remediation=f"Publish valid SPF and enforced DMARC records (p=quarantine or p=reject) in authoritative DNS.",
                    )
                )
                total_score += inc

        # ------------------------------------------------------------------
        # 4. DOMAIN MODULE: SSL & HTTP Security Headers
        # ------------------------------------------------------------------
        elif module == "domain":
            http_data = data.get("http", {}) if isinstance(data.get("http"), dict) else {}
            sec_score = http_data.get("security_score", "A")
            ssl_data = data.get("ssl", {}) if isinstance(data.get("ssl"), dict) else {}
            ssl_valid = ssl_data.get("valid", True)

            # SSL Certificate expired or invalid
            if not ssl_valid and ssl_data:
                inc = 1.2
                factors.append(
                    ScoringFactor(
                        name="Invalid or Expired SSL/TLS Certificate",
                        module="domain",
                        indicator=str(target),
                        raw_metric="SSL validation failed",
                        weight=1.5,
                        contribution=inc,
                        severity="HIGH",
                        confidence="CONFIRMED",
                        evidence="TLS certificate validation failed, expired, or self-signed. Exposes users to MitM attacks.",
                        remediation="Deploy valid certificate issued by a trusted public CA with automated ACME renewal.",
                    )
                )
                total_score += inc

            # HTTP Security Header Configuration (NOT Critical; maximum 0.8)
            if sec_score in ["F", "D"]:
                inc = 0.7
                missing_hdrs = http_data.get("missing_headers", [])
                factors.append(
                    ScoringFactor(
                        name="Missing HTTP Hardening Headers",
                        module="domain",
                        indicator=str(target),
                        raw_metric=f"Header Security Grade: {sec_score}",
                        weight=0.8,
                        contribution=inc,
                        severity="LOW",
                        confidence="HIGH",
                        evidence=f"Web server missing baseline protection headers: {', '.join(missing_hdrs[:4]) if missing_hdrs else 'CSP, HSTS, X-Content-Type'}.",
                        remediation="Configure web server to emit Strict-Transport-Security, Content-Security-Policy, and X-Frame-Options headers.",
                    )
                )
                total_score += inc

        # ------------------------------------------------------------------
        # 5. USERNAME MODULE: Platform Surface
        # ------------------------------------------------------------------
        elif module == "username":
            summary = data.get("summary") or {}
            found = summary.get("total_found", 0) if isinstance(summary, dict) else 0
            if found >= 8:
                inc = 0.5
                factors.append(
                    ScoringFactor(
                        name="Broad Public Identity Footprint",
                        module="username",
                        indicator=str(target),
                        raw_metric=f"Active on {found} public platforms",
                        weight=0.5,
                        contribution=inc,
                        severity="INFO",
                        confidence="HIGH",
                        evidence=f"Username was discovered active across {found} online accounts, expanding OSINT exposure surface.",
                        remediation="Audit personal privacy settings and delete unused public social media or developer accounts.",
                    )
                )
                total_score += inc

    # ------------------------------------------------------------------
    # SCORE AGGREGATION & NORMALIZATION
    # ------------------------------------------------------------------
    # Cap final deterministic score at 10.0
    final_score = round(min(10.0, total_score), 1)

    # Calculate severity & confidence distributions
    sev_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    conf_dist = {"CONFIRMED": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for fac in factors:
        if fac.severity in sev_dist:
            sev_dist[fac.severity] += 1
        if fac.confidence in conf_dist:
            conf_dist[fac.confidence] += 1

    # Determine Overall Risk Level based on both score and maximum severity
    if final_score == 0.0:
        risk_level = "SAFE"
        org_impact = "NEGLIGIBLE"
        status_label = "CLEAN"
        summary_stmt = "No verified malicious indicators, exploitable service exposures, or compromised records were observed."
    elif final_score >= 8.5 or sev_dist["CRITICAL"] >= 1:
        risk_level = "CRITICAL"
        org_impact = "CRITICAL"
        status_label = "IMMEDIATE_ACTION_REQUIRED"
        summary_stmt = f"Critical threats identified (score: {final_score}/10). Immediate containment and defensive remediation are required."
    elif final_score >= 6.0 or sev_dist["HIGH"] >= 2:
        risk_level = "HIGH"
        org_impact = "HIGH"
        status_label = "ELEVATED_THREAT"
        summary_stmt = f"High-risk indicators discovered (score: {final_score}/10). Remediation should be prioritized by the security team."
    elif final_score >= 3.5 or sev_dist["MEDIUM"] >= 2:
        risk_level = "MEDIUM"
        org_impact = "ELEVATED"
        status_label = "REVIEW_RECOMMENDED"
        summary_stmt = f"Moderate security exposures observed (score: {final_score}/10). Review configuration weaknesses and exposed attack surface."
    else:
        risk_level = "LOW"
        org_impact = "LOW"
        status_label = "MONITORING_SUFFICIENT"
        summary_stmt = f"Low risk profile detected (score: {final_score}/10). Minor configuration notes or informational observations only."

    # Overall Confidence Calculation
    if conf_dist["CONFIRMED"] >= 1 or conf_dist["HIGH"] >= 2:
        overall_confidence = "HIGH"
    elif conf_dist["MEDIUM"] >= 1:
        overall_confidence = "MEDIUM"
    else:
        overall_confidence = "LOW"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "organizational_impact": org_impact,
        "confidence": overall_confidence,
        "status": status_label,
        "summary_statement": summary_stmt,
        "factors_count": len(factors),
        "scoring_factors": [f.to_dict() for f in factors],
        "severity_distribution": sev_dist,
        "confidence_distribution": conf_dist,
    }
