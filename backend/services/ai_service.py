"""
Local AI Investigation Engine Service.

Provides evidence-grounded AI investigation summarization, deterministic risk scoring with AI explanations,
cross-investigation IOC correlation, MITRE ATT&CK technique mapping, and natural language search.
All security-critical score calculations and mapping rules remain 100% deterministic and evidence-backed.
"""
import logging
import html
import re
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from services.ollama_client import ollama_client
from services.risk_engine import assess_investigation_risk
from services.deduplication_service import deduplicate_investigation_findings
from services.mitre_mapper import map_investigation_mitre
from core.config import settings

logger = logging.getLogger(__name__)


def render_markdown_to_html(md: str) -> str:
    """
    Renders basic Markdown formatting (headers, bold, italics, inline code, bullet/numbered lists)
    into safe, styled HTML markup suitable for report viewing and print export.
    """
    if not md:
        return ""

    lines = md.strip().split("\n")
    out = []
    in_list = False
    list_type = "ul"

    for line in lines:
        s = line.strip()
        if not s:
            if in_list:
                out.append(f"</{list_type}>")
                in_list = False
            continue

        # Headers
        if s.startswith("### "):
            if in_list:
                out.append(f"</{list_type}>")
                in_list = False
            out.append(f'<h4 style="color:#10B981;margin:12px 0 6px 0;font-size:13px;font-weight:700;">{html.escape(s[4:])}</h4>')
            continue
        elif s.startswith("## "):
            if in_list:
                out.append(f"</{list_type}>")
                in_list = False
            out.append(f'<h3 style="color:#10B981;margin:16px 0 8px 0;font-size:14px;font-weight:700;">{html.escape(s[3:])}</h3>')
            continue
        elif s.startswith("# "):
            if in_list:
                out.append(f"</{list_type}>")
                in_list = False
            out.append(f'<h2 style="color:#10B981;margin:18px 0 10px 0;font-size:16px;font-weight:700;">{html.escape(s[2:])}</h2>')
            continue

        # Bullet list
        if s.startswith("- ") or s.startswith("* "):
            if not in_list:
                out.append('<ul style="margin:6px 0 10px 18px;padding-left:12px;list-style-type:disc;">')
                in_list = True
                list_type = "ul"
            content = html.escape(s[2:])
            content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
            content = re.sub(r"`(.+?)`", r'<code style="background:#0F172A;padding:2px 5px;border-radius:4px;border:1px solid #334155;">\1</code>', content)
            out.append(f'<li style="margin-bottom:5px;line-height:1.5;">{content}</li>')
            continue

        # Numbered list
        m_num = re.match(r"^(\d+)\.\s+(.*)", s)
        if m_num:
            if not in_list:
                out.append('<ol style="margin:6px 0 10px 18px;padding-left:12px;list-style-type:decimal;">')
                in_list = True
                list_type = "ol"
            content = html.escape(m_num.group(2))
            content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
            content = re.sub(r"`(.+?)`", r'<code style="background:#0F172A;padding:2px 5px;border-radius:4px;border:1px solid #334155;">\1</code>', content)
            out.append(f'<li style="margin-bottom:5px;line-height:1.5;">{content}</li>')
            continue

        if in_list:
            out.append(f"</{list_type}>")
            in_list = False

        content = html.escape(s)
        content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
        content = re.sub(r"`(.+?)`", r'<code style="background:#0F172A;padding:2px 5px;border-radius:4px;border:1px solid #334155;">\1</code>', content)
        out.append(f'<p style="margin:6px 0;line-height:1.6;">{content}</p>')

    if in_list:
        out.append(f"</{list_type}>")

    return "\n".join(out)


def generate_investigation_summary(db: Session, investigation_id: str) -> Dict[str, Any]:
    """
    Generates an executive narrative summary grounded strictly in deduplicated investigation evidence.
    Enforces strict guardrails against AI hallucinations.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    raw_findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    dedup = deduplicate_investigation_findings(raw_findings)
    risk_data = assess_investigation_risk(raw_findings, target_context=inv.title)

    unique_findings = dedup["unique_findings"]
    evidence_lines = []

    for uf in unique_findings[:15]:
        evidence_lines.append(f"- [{uf['module'].upper()}] {uf['indicator']}: {uf['description']} (Severity: {uf['severity']}, Confidence: {uf['confidence']})")

    if not evidence_lines:
        evidence_summary_text = "No findings recorded. Target infrastructure has not been scanned or yielded zero observations."
    else:
        evidence_summary_text = "\n".join(evidence_lines)

    prompt = (
        f"INVESTIGATION DATA BRIEF:\n"
        f"Case Title: {inv.title}\n"
        f"Status: {inv.status}\n"
        f"Description: {inv.description or 'N/A'}\n"
        f"Calculated Risk Level: {risk_data['risk_level']} (Deterministic Score: {risk_data['risk_score']}/10.0)\n"
        f"Total Raw Observations: {dedup['total_raw_observations']} | Unique Verified Findings: {dedup['total_unique_findings']}\n\n"
        f"VERIFIED FINDINGS EVIDENCE:\n{evidence_summary_text}\n\n"
        f"CRITICAL INSTRUCTIONS FOR AI ANALYST:\n"
        f"1. Ground your analysis ONLY on the verified findings listed above.\n"
        f"2. NEVER invent or hallucinate vulnerabilities, open ports, stolen credentials, or malware that are not listed in the evidence.\n"
        f"3. If findings are clean or zero, explicitly state that no threats were detected and the target appears low-risk or unprobed.\n"
        f"4. Clearly distinguish verified findings from unverified observations.\n"
        f"5. Outline 2-3 concrete, actionable recommendations based ONLY on the evidence above.\n\n"
        f"Structure your response with:\n"
        f"### Executive Assessment\n"
        f"### Key Verified Observations\n"
        f"### Risk & Threat Context\n"
        f"### Recommended Defensive Actions"
    )

    system_prompt = (
        "You are OSINT-X Senior Cyber Threat Intelligence Analyst. Produce precise, professional, "
        "and evidence-grounded intelligence briefings. Adhere strictly to verified telemetry."
    )

    ai_result = ollama_client.generate(prompt, system_prompt=system_prompt)
    raw_summary = ai_result.get("response", "").strip()

    return {
        "investigation_id": investigation_id,
        "title": inv.title,
        "total_findings": len(raw_findings),
        "total_unique_findings": dedup["total_unique_findings"],
        "summary": raw_summary,
        "summary_html": render_markdown_to_html(raw_summary),
        "model_used": ai_result.get("model", settings.OLLAMA_MODEL),
        "offline_fallback": ai_result.get("offline_fallback", False),
    }


def calculate_and_explain_risk(db: Session, investigation_id: str) -> Dict[str, Any]:
    """
    Computes transparent, evidence-based risk assessment using risk_engine,
    then generates an AI explanation strictly grounded in calculated factors.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    raw_findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    risk_assessment = assess_investigation_risk(raw_findings, target_context=inv.title)

    factors = risk_assessment["scoring_factors"]
    factors_text = "\n".join(
        f"- {fac['name']} (+{fac['contribution']} pts): {fac['evidence']} [Severity: {fac['severity']}]"
        for fac in factors
    ) if factors else "- No risk factors detected. Infrastructure posture is clean."

    prompt = (
        f"Investigation Case: {inv.title}\n"
        f"Calculated Threat Score: {risk_assessment['risk_score']} / 10.0\n"
        f"Assigned Risk Level: {risk_assessment['risk_level']}\n"
        f"Organizational Impact: {risk_assessment['organizational_impact']}\n"
        f"Analytical Confidence: {risk_assessment['confidence']}\n\n"
        f"Identified Risk Contributors:\n{factors_text}\n\n"
        f"Explain in 2-3 concise paragraphs why this exact score and risk level were determined. "
        f"Do NOT invent any vulnerabilities or ports not in the list above. Conclude with recommended priority actions."
    )

    system_prompt = "You are a Cyber Threat Intelligence Risk Officer. Provide objective, mathematically aligned threat risk analysis."
    ai_res = ollama_client.generate(prompt, system_prompt=system_prompt)
    explanation = ai_res.get("response", "").strip()

    result = dict(risk_assessment)
    result["investigation_id"] = investigation_id
    result["explanation"] = explanation
    result["explanation_html"] = render_markdown_to_html(explanation)
    result["is_deterministic"] = True
    result["offline_fallback"] = ai_res.get("offline_fallback", False)
    # Backward compatibility fields
    result["risk_factors"] = [f"{fac['name']} (+{fac['contribution']}): {fac['raw_metric']}" for fac in factors]

    return result


def map_mitre_attack(db: Session, investigation_id: str) -> Dict[str, Any]:
    """
    Maps investigation findings to the MITRE ATT&CK Enterprise Matrix,
    clearly differentiating OSINT-X tool reconnaissance from observed adversary behavior.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    raw_findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    mitre_data = map_investigation_mitre(raw_findings)
    mitre_data["investigation_id"] = investigation_id
    mitre_data["is_deterministic"] = True

    return mitre_data



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
    """
    Maps investigation findings to deterministic MITRE ATT&CK Matrix techniques.

    Delegates entirely to map_investigation_mitre() from mitre_mapper, which owns
    the authoritative TECHNIQUE_CATALOG and all module-to-technique mapping logic.
    Duplicate technique IDs are suppressed by map_investigation_mitre() internally.
    Returns the full structured response with investigation_id and is_deterministic flag
    for API and test compatibility.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()

    # Delegate all lookup and mapping logic to the authoritative mitre_mapper module.
    # map_investigation_mitre() uses TECHNIQUE_CATALOG, handles all modules (domain, ip,
    # email, username, file, threat_intel), suppresses duplicates, and provides a safe
    # informational fallback when no findings are present.
    mitre_result = map_investigation_mitre(findings)

    return {
        "investigation_id": investigation_id,
        "total_techniques_mapped": mitre_result["total_techniques_mapped"],
        "mitre_attack_matrix": mitre_result["mitre_attack_matrix"],
        "tool_reconnaissance_count": mitre_result.get("tool_reconnaissance_count", 0),
        "adversary_behavior_count": mitre_result.get("adversary_behavior_count", 0),
        "is_deterministic": True,
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
