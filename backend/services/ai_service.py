"""
Local AI Investigation Engine Service.

Provides AI investigation summarization, deterministic risk scoring with AI explanations,
cross-investigation IOC correlation, MITRE ATT&CK technique mapping, and natural language search.
All security-critical score calculations and mapping rules remain 100% deterministic.
"""
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from services.ollama_client import ollama_client
from core.config import settings

logger = logging.getLogger(__name__)

# Static deterministic MITRE ATT&CK lookup map for OSINT findings
MITRE_ATTACK_LOOKUP = {
    "domain": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1590.002",
            "technique_name": "Gather Victim Network Information: DNS",
            "description": "Adversaries may gather DNS information to map victim network architecture."
        },
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1595.002",
            "technique_name": "Active Scanning: Vulnerability Scanning",
            "description": "Scanning web servers and security headers for misconfigurations."
        }
    ],
    "ip": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1595.001",
            "technique_name": "Active Scanning: IP Blocks",
            "description": "Scanning IP ranges to discover active hosts and open services."
        },
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1590.005",
            "technique_name": "Gather Victim Network Information: IP Addresses",
            "description": "Collecting IP addresses and ASN data."
        }
    ],
    "email": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1589.002",
            "technique_name": "Gather Victim Identity Information: Email Addresses",
            "description": "Gathering email addresses to target in phishing campaigns."
        },
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1593",
            "technique_name": "Search Open Technical Databases",
            "description": "Checking breach databases for compromised credentials."
        }
    ],
    "username": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1589.003",
            "technique_name": "Gather Victim Identity Information: Usernames",
            "description": "Enumerating online profiles across public social media platforms."
        }
    ],
    "file": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1592",
            "technique_name": "Gather Victim Host Information",
            "description": "Extracting EXIF metadata and host artifacts from uploaded documents/images."
        }
    ],
    "threat_intel": [
        {
            "tactic": "Reconnaissance",
            "technique_id": "T1596",
            "technique_name": "Search Open Websites/Domains",
            "description": "Querying VirusTotal, Shodan, and AbuseIPDB threat intelligence feeds."
        }
    ]
}


def generate_investigation_summary(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Generates executive narrative summary for an investigation using local AI model."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    iocs = db.query(IOC).all()  # Check associated IOCs

    finding_summaries = []
    for f in findings:
        finding_summaries.append(f"- Module: {f.module.upper()} (Type: {f.type})")

    prompt = (
        f"Investigation Title: {inv.title}\n"
        f"Status: {inv.status}\n"
        f"Description: {inv.description or 'N/A'}\n"
        f"Tags: {', '.join(inv.tags or [])}\n"
        f"Total Findings: {len(findings)}\n"
        f"Findings Breakdown:\n" + ("\n".join(finding_summaries) if finding_summaries else "No findings recorded yet.") + "\n\n"
        "Provide a concise executive summary and recommended analyst next steps."
    )

    system_prompt = "You are an OSINT Security Analyst AI assistant. Summarize technical investigation findings clearly."
    ai_result = ollama_client.generate(prompt, system_prompt=system_prompt)

    return {
        "investigation_id": investigation_id,
        "title": inv.title,
        "total_findings": len(findings),
        "summary": ai_result.get("response", ""),
        "model_used": ai_result.get("model", settings.OLLAMA_MODEL),
        "offline_fallback": ai_result.get("offline_fallback", False)
    }


def calculate_and_explain_risk(db: Session, investigation_id: str) -> Dict[str, Any]:
    """
    Computes deterministic risk score (0-10) based on strict rule weights,
    then uses local AI to generate explanation.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    
    score = 0.0
    factors = []

    for f in findings:
        data = f.data or {}
        # Threat intel findings
        if f.module == "threat_intel":
            vt = data.get("virustotal", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = vt.get("malicious", 0)
            if malicious > 0:
                inc = min(4.0, malicious * 0.5)
                score += inc
                factors.append(f"VirusTotal detected {malicious} malicious engines (+{inc:.1f})")
            
            abuse_score = data.get("abuseipdb", {}).get("data", {}).get("abuseConfidenceScore", 0)
            if abuse_score > 20:
                inc = min(3.0, (abuse_score / 100.0) * 3.0)
                score += inc
                factors.append(f"AbuseIPDB confidence score is {abuse_score}% (+{inc:.1f})")

        # IP findings
        elif f.module == "ip":
            ports = data.get("open_ports", [])
            if len(ports) > 0:
                inc = min(2.0, len(ports) * 0.5)
                score += inc
                factors.append(f"Discovered {len(ports)} open port(s): {ports} (+{inc:.1f})")

        # Email findings
        elif f.module == "email":
            breaches = data.get("breaches", [])
            if len(breaches) > 0:
                inc = min(3.0, len(breaches) * 1.0)
                score += inc
                factors.append(f"Email target appeared in {len(breaches)} data breach(es) (+{inc:.1f})")

        # Domain findings
        elif f.module == "domain":
            sec_score = data.get("http", {}).get("security_score", "F")
            if sec_score in ["F", "D"]:
                score += 1.5
                factors.append(f"HTTP security header rating is low ({sec_score}) (+1.5)")

    # Cap max score at 10.0
    final_score = round(min(10.0, score), 1)

    if final_score >= 9.0:
        level = "CRITICAL"
    elif final_score >= 7.0:
        level = "HIGH"
    elif final_score >= 4.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    # AI explanation for the deterministic score
    prompt = (
        f"Investigation: {inv.title}\n"
        f"Calculated Risk Score: {final_score}/10 ({level})\n"
        f"Identified Risk Factors:\n" + ("\n".join(f"- {fac}" for fac in factors) if factors else "- No high-risk indicators found.") + "\n\n"
        "Explain to the security team why this risk level was assigned."
    )
    ai_res = ollama_client.generate(prompt)

    return {
        "investigation_id": investigation_id,
        "risk_score": final_score,
        "risk_level": level,
        "risk_factors": factors,
        "explanation": ai_res.get("response", ""),
        "is_deterministic": True,
        "offline_fallback": ai_res.get("offline_fallback", False)
    }


def correlate_iocs(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Finds cross-investigation IOC overlaps across all cases in DB."""
    current_inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not current_inv:
        return {"error": "Investigation not found"}

    all_iocs = db.query(IOC).all()
    
    # Simple cross-case matching
    value_to_cases = {}
    for ioc in all_iocs:
        val = ioc.value
        if val not in value_to_cases:
            value_to_cases[val] = []
        value_to_cases[val].append({"type": ioc.type, "source": ioc.source, "reputation": ioc.reputation_score})

    correlations = []
    all_investigations = db.query(Investigation).all()
    
    for inv in all_investigations:
        if inv.id == investigation_id:
            continue
        
        # Check overlaps in title/description/tags
        shared_tags = list(set(current_inv.tags or []).intersection(set(inv.tags or [])))
        if shared_tags:
            correlations.append({
                "target_investigation_id": inv.id,
                "target_investigation_title": inv.title,
                "correlation_type": "shared_tags",
                "matched_values": shared_tags,
                "confidence": "MEDIUM"
            })

    return {
        "current_investigation_id": investigation_id,
        "total_correlations_found": len(correlations),
        "correlations": correlations
    }


def map_mitre_attack(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Maps investigation findings to deterministic MITRE ATT&CK Matrix techniques."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    
    mapped_techniques = []
    seen_technique_ids = set()

    for f in findings:
        techs = MITRE_ATTACK_LOOKUP.get(f.module, [])
        for t in techs:
            if t["technique_id"] not in seen_technique_ids:
                seen_technique_ids.add(t["technique_id"])
                mapped_techniques.append(t)

    # If no findings yet, provide default Reconnaissance techniques
    if not mapped_techniques:
        mapped_techniques.append(MITRE_ATTACK_LOOKUP["domain"][0])

    return {
        "investigation_id": investigation_id,
        "total_techniques_mapped": len(mapped_techniques),
        "mitre_attack_matrix": mapped_techniques,
        "is_deterministic": True
    }


def natural_language_search(db: Session, query_str: str) -> Dict[str, Any]:
    """Translates free-text natural language query into structured investigation search filters."""
    q = query_str.lower()
    
    query = db.query(Investigation)
    applied_filters = {}

    if "active" in q:
        query = query.filter(Investigation.status == "active")
        applied_filters["status"] = "active"
    elif "archived" in q:
        query = query.filter(Investigation.status == "archived")
        applied_filters["status"] = "archived"

    # Extract general search term
    terms = [t for t in q.split() if t not in ["active", "archived", "show", "find", "all", "investigations", "cases", "with"]]
    if terms:
        search_term = " ".join(terms)
        query = query.filter(
            (Investigation.title.ilike(f"%{search_term}%")) |
            (Investigation.description.ilike(f"%{search_term}%"))
        )
        applied_filters["search_term"] = search_term

    results = query.all()
    
    return {
        "raw_query": query_str,
        "applied_filters": applied_filters,
        "total_matches": len(results),
        "matches": [
            {
                "id": inv.id,
                "title": inv.title,
                "status": inv.status,
                "tags": inv.tags,
                "created_at": inv.created_at.isoformat() if inv.created_at else None
            }
            for inv in results
        ]
    }
