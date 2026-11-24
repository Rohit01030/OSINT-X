"""
Report Generator Service for OSINT-X.

Compiles comprehensive Cyber Threat Intelligence Reports adhering to professional SOC,
threat intelligence, and commercial security assessment standards.
Generates:
  1. Structured JSON Intelligence Model (21 sections)
  2. Multi-section Tabular CSV Export
  3. Publication-Ready Executive HTML/PDF Report with Dark Navy / Emerald Theme and Print-Ready CSS
"""
import json
import csv
import io
import html
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from models.consent_log import ConsentLog
from models.report import Report
from models.user import User

from services import ai_service, visualization_service
from services.risk_engine import assess_investigation_risk
from services.deduplication_service import deduplicate_investigation_findings
from services.correlation_engine import correlate_investigation_indicators
from services.mitre_mapper import map_investigation_mitre

logger = logging.getLogger(__name__)


def generate_json_report(
    db: Session,
    investigation_id: str,
    classification: str = "TLP:AMBER",
    analyst_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compiles full 21-section structured intelligence data model for an investigation.
    Performs deterministic deduplication, risk assessment, and IOC correlation.
    """
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    raw_findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    all_iocs = db.query(IOC).all()
    consent_logs = db.query(ConsentLog).filter(ConsentLog.investigation_id == investigation_id).all()

    # Determine creator/analyst name
    if not analyst_name and inv.created_by:
        creator = db.query(User).filter(User.id == inv.created_by).first()
        if creator:
            analyst_name = f"{creator.username} ({creator.role})"
    if not analyst_name:
        analyst_name = "OSINT-X Lead Intelligence Analyst"

    # 1. Deduplication Engine
    dedup_results = deduplicate_investigation_findings(raw_findings)
    unique_findings = dedup_results["unique_findings"]

    # 2. Evidence-Based Risk Assessment
    risk_assessment = assess_investigation_risk(raw_findings, target_context=inv.title)

    # 3. IOC Correlation Engine
    correlation_results = correlate_investigation_indicators(raw_findings, all_iocs)

    # 4. MITRE ATT&CK Mapping
    mitre_results = map_investigation_mitre(raw_findings)

    # 5. AI Executive Summary & Risk Explanation
    ai_summary_obj = ai_service.generate_investigation_summary(db, investigation_id)
    ai_risk_obj = ai_service.calculate_and_explain_risk(db, investigation_id)

    # 6. Module-Specific Intelligence Grouping
    module_intel: Dict[str, List[Dict[str, Any]]] = {
        "domain": [],
        "ip": [],
        "email": [],
        "username": [],
        "file": [],
        "threat_intel": [],
    }
    targets_seen = set()
    for f in raw_findings:
        m = getattr(f, "module", "")
        d = getattr(f, "data", {})
        if m in module_intel and isinstance(d, dict):
            module_intel[m].append(d)
            t = d.get("target") or d.get("domain") or d.get("ip")
            if t:
                targets_seen.add(str(t))

    primary_target = list(targets_seen)[0] if targets_seen else inv.title

    # 7. Attack Surface Synthesis & Recommendations
    attack_surface = _synthesize_attack_surface(unique_findings, risk_assessment)
    recommendations = _synthesize_recommendations(unique_findings, risk_assessment)
    limitations = _synthesize_limitations(raw_findings)

    # 8. Visual Chart Metrics
    metrics = visualization_service.get_chart_metrics(db, investigation_id)

    gen_time = datetime.now(timezone.utc).isoformat()

    report_payload = {
        "report_metadata": {
            "platform": "OSINT-X Threat Intelligence Platform",
            "report_version": "2.0.0",
            "investigation_id": inv.id,
            "case_id": inv.id[:8].upper(),
            "title": inv.title,
            "status": inv.status.upper(),
            "target": primary_target,
            "classification": classification,
            "analyst": analyst_name,
            "description": inv.description or "Automated multi-source cyber threat intelligence investigation.",
            "tags": inv.tags or [],
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "generated_at": gen_time,
        },
        "executive_summary": {
            "narrative": ai_summary_obj.get("summary", ""),
            "narrative_html": ai_summary_obj.get("summary_html", ""),
            "overall_risk_level": risk_assessment["risk_level"],
            "risk_score": risk_assessment["risk_score"],
            "confidence": risk_assessment["confidence"],
            "organizational_impact": risk_assessment["organizational_impact"],
            "status_statement": risk_assessment["summary_statement"],
        },
        "investigation_scope": {
            "primary_target": primary_target,
            "all_targets_identified": list(targets_seen),
            "authorized_scope": "Passive OSINT Reconnaissance, Open-Source Threat Telemetry, Authorized Port Probing",
            "investigation_type": "Cyber Threat Intelligence & Attack Surface Analysis",
            "jurisdiction": "Authorized Internal Security Audit",
        },
        "methodology": {
            "frameworks": ["MITRE ATT&CK Enterprise", "OSINT Framework", "NIST SP 800-115"],
            "collection_types": ["Passive DNS & WHOIS", "Certificate Transparency Logs", "Active Non-Destructive Sockets", "Public Breach Repositories", "Multi-Vendor Threat Feeds"],
            "risk_model": "Evidence-Weighted Deterministic Scoring (0-10)",
        },
        "tools_and_sources": [
            {"name": "Authoritative DNS Resolver", "role": "DNS Zone & Record Enumeration", "type": "Active Passive"},
            {"name": "WHOIS / RDAP Registry", "role": "Domain Registrar & Autonomous System Info", "type": "Public Registry"},
            {"name": "X.509 SSL/TLS Auditing", "role": "Certificate Validity & SAN Extraction", "type": "Cryptographic Audit"},
            {"name": "VirusTotal Multi-Scanner", "role": "Anti-Virus Engine File & Domain Blacklist Check", "type": "Threat Feed"},
            {"name": "AbuseIPDB Threat Database", "role": "Crowdsourced IP Abuse Telemetry", "type": "Reputation Database"},
            {"name": "HaveIBeenPwned (HIBP)", "role": "Data Breach & Credential Compromise Verification", "type": "Breach Repository"},
            {"name": "Ollama Local AI Engine", "role": "Evidence-Grounded Intelligence Synthesis", "type": "Private AI Inference"},
        ],
        "investigation_statistics": {
            "total_raw_observations": dedup_results["total_raw_observations"],
            "total_unique_findings": dedup_results["total_unique_findings"],
            "duplicate_observations_merged": dedup_results["duplicate_observations_count"],
            "severity_distribution": dedup_results["severity_distribution"],
            "confidence_distribution": risk_assessment["confidence_distribution"],
            "total_iocs_registered": len(all_iocs),
            "total_correlations_identified": correlation_results["total_correlations"],
        },
        "risk_assessment": {
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "organizational_impact": risk_assessment["organizational_impact"],
            "confidence": risk_assessment["confidence"],
            "scoring_factors": risk_assessment["scoring_factors"],
            "risk_factors": risk_assessment.get("risk_factors", []),
            "explanation": ai_risk_obj.get("explanation", ""),
            "explanation_html": ai_risk_obj.get("explanation_html", ""),
        },
        "technical_findings": unique_findings,
        "module_intelligence": module_intel,
        "ioc_correlations": correlation_results,
        "mitre_attack": mitre_results,
        "mitre_attack_matrix": mitre_results.get("mitre_attack_matrix", []),
        "potential_attack_surface": attack_surface,
        "recommendations": recommendations,
        "investigation_limitations": limitations,
        "evidence_and_references": [
            {
                "id": getattr(i, "id", "ioc"),
                "value": getattr(i, "value", ""),
                "type": getattr(i, "type", "IOC").upper(),
                "source": getattr(i, "source", "module") or "module",
                "reputation_score": getattr(i, "reputation_score", 0.0),
                "first_seen": i.first_seen.isoformat() if getattr(i, "first_seen", None) else None,
                "last_seen": i.last_seen.isoformat() if getattr(i, "last_seen", None) else None,
            }
            for i in all_iocs
            if hasattr(i, "value")
        ],
        "appendix_raw_observations": [
            {
                "id": getattr(f, "id", ""),
                "module": getattr(f, "module", "").upper(),
                "type": getattr(f, "type", ""),
                "target": (getattr(f, "data", {}) or {}).get("target", "N/A"),
                "created_at": f.created_at.isoformat() if getattr(f, "created_at", None) else None,
            }
            for f in raw_findings
        ],
        "consent_audit_trail": [
            {
                "id": getattr(c, "id", str(idx)),
                "target": getattr(c, "target", "N/A"),
                "confirmed_at": c.confirmed_at.isoformat() if getattr(c, "confirmed_at", None) else None,
                "ip_address": getattr(c, "ip_address", "N/A"),
            }
            for idx, c in enumerate(consent_logs)
            if hasattr(c, "target") or hasattr(c, "ip_address")
        ],
        # Backward compatibility aliases
        "findings": [
            {
                "id": f.id,
                "module": f.module,
                "type": f.type,
                "data": f.data,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in raw_findings
        ],
        "iocs": [
            {
                "id": i.id,
                "value": i.value,
                "type": i.type,
                "source": i.source,
                "reputation_score": i.reputation_score,
            }
            for i in all_iocs
        ],
        "metrics_summary": metrics.get("module_distribution", {}),
    }

    return report_payload


def generate_csv_report(db: Session, investigation_id: str) -> str:
    """Formats investigation intelligence into structured multi-table CSV data."""
    rep = generate_json_report(db, investigation_id)
    if "error" in rep:
        return f"Error: {rep['error']}"

    output = io.StringIO()
    writer = csv.writer(output)

    meta = rep["report_metadata"]
    risk = rep["risk_assessment"]
    stats = rep["investigation_statistics"]

    # 1. Header Metadata
    writer.writerow(["=== OSINT-X INVESTIGATION REPORT ==="])
    writer.writerow(["Case ID", meta["case_id"]])
    writer.writerow(["Investigation Title", meta["title"]])
    writer.writerow(["Classification", meta["classification"]])
    writer.writerow(["Status", meta["status"]])
    writer.writerow(["Lead Analyst", meta["analyst"]])
    writer.writerow(["Generated At (UTC)", meta["generated_at"]])
    writer.writerow(["Target", meta["target"]])
    writer.writerow(["Overall Risk Level", f"{risk['risk_level']} (Score: {risk['risk_score']}/10.0)"])
    writer.writerow(["Total Observations", stats["total_raw_observations"]])
    writer.writerow(["Unique Findings", stats["total_unique_findings"]])
    writer.writerow(["Duplicates Merged", stats["duplicate_observations_merged"]])
    writer.writerow([])

    # 2. Deduplicated Technical Findings
    writer.writerow(["=== DEDUPLICATED TECHNICAL FINDINGS ==="])
    writer.writerow([
        "Fingerprint",
        "Module",
        "Type",
        "Indicator",
        "Severity",
        "Confidence",
        "Observations Count",
        "First Seen",
        "Last Seen",
        "Finding Description",
        "Remediation",
    ])
    for uf in rep["technical_findings"]:
        writer.writerow([
            uf["fingerprint"],
            uf["module"].upper(),
            uf["type"],
            uf["indicator"],
            uf["severity"],
            uf["confidence"],
            uf["observation_count"],
            uf["first_seen"],
            uf["last_seen"],
            uf["description"],
            uf["remediation"],
        ])
    writer.writerow([])

    # 3. Risk Scoring Breakdown
    writer.writerow(["=== RISK ASSESSMENT SCORING BREAKDOWN ==="])
    writer.writerow(["Risk Factor Name", "Module", "Indicator", "Metric Evidence", "Weight", "Contribution", "Severity", "Confidence"])
    for fac in risk["scoring_factors"]:
        writer.writerow([
            fac["name"],
            fac["module"].upper(),
            fac["indicator"],
            fac["raw_metric"],
            fac["weight"],
            fac["contribution"],
            fac["severity"],
            fac["confidence"],
        ])
    writer.writerow([])

    # 4. IOC Correlations
    writer.writerow(["=== INTELLIGENCE CORRELATION & RELATIONSHIPS ==="])
    writer.writerow(["Source Indicator", "Source Type", "Relationship", "Target Indicator", "Target Type", "Confidence", "Evidence"])
    for rel in rep["ioc_correlations"].get("relationships", []):
        writer.writerow([
            rel["source"],
            rel["source_type"],
            rel["relationship"],
            rel["target"],
            rel["target_type"],
            rel["confidence"],
            rel["evidence"],
        ])
    writer.writerow([])

    # 5. MITRE ATT&CK Mappings
    writer.writerow(["=== MITRE ATT&CK MATRIX RECON MAPPINGS ==="])
    writer.writerow(["Technique ID", "Tactic", "Technique Name", "Mapping Type", "Confidence", "Evidence"])
    for m in rep["mitre_attack"].get("mitre_attack_matrix", []):
        writer.writerow([
            m["technique_id"],
            m["tactic"],
            m["technique_name"],
            m.get("mapping_type", "TOOL_COLLECTION_ACTIVITY"),
            m.get("confidence", "HIGH"),
            m.get("evidence", ""),
        ])
    writer.writerow([])

    # 6. Registered Indicators of Compromise (IOCs)
    writer.writerow(["=== REGISTERED INDICATORS OF COMPROMISE (IOCs) ==="])
    writer.writerow(["IOC ID", "Indicator Value", "Type", "Source Provider", "Reputation Score", "First Seen", "Last Seen"])
    for i in rep["evidence_and_references"]:
        writer.writerow([
            i["id"],
            i["value"],
            i["type"],
            i["source"],
            i["reputation_score"],
            i["first_seen"],
            i["last_seen"],
        ])

    return output.getvalue()


def generate_html_pdf_report(
    db: Session,
    investigation_id: str,
    classification: str = "TLP:AMBER",
) -> str:
    """
    Renders publication-grade, responsive HTML Cyber Threat Intelligence Report.
    Designed with a professional dark navy / subtle emerald palette, Inter/Roboto typography,
    and print-specific CSS for direct PDF export.
    """
    rep = generate_json_report(db, investigation_id, classification=classification)
    if "error" in rep:
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title></head>
        <body style="background:#0B1120;color:#F8FAFC;font-family:sans-serif;padding:40px;text-align:center;">
        <h1 style="color:#EF4444;">Investigation Error</h1>
        <p>{html.escape(rep['error'])}</p></body></html>"""

    meta = rep["report_metadata"]
    exec_sum = rep["executive_summary"]
    risk = rep["risk_assessment"]
    stats = rep["investigation_statistics"]
    unique_findings = rep["technical_findings"]
    scoring_factors = risk.get("scoring_factors", [])
    correlations = rep["ioc_correlations"].get("relationships", [])
    mitre_list = rep["mitre_attack"].get("mitre_attack_matrix", [])
    mod_intel = rep["module_intelligence"]
    recommendations = rep["recommendations"]
    attack_surface = rep["potential_attack_surface"]
    limitations = rep["investigation_limitations"]
    iocs_list = rep["evidence_and_references"]
    raw_obs = rep["appendix_raw_observations"]

    # Severity color helper
    def sev_badge(s: str) -> str:
        s_up = (s or "").upper()
        if s_up == "CRITICAL":
            return '<span class="badge badge-critical">CRITICAL</span>'
        elif s_up == "HIGH":
            return '<span class="badge badge-high">HIGH</span>'
        elif s_up == "MEDIUM":
            return '<span class="badge badge-medium">MEDIUM</span>'
        elif s_up == "LOW":
            return '<span class="badge badge-low">LOW</span>'
        elif s_up == "SAFE":
            return '<span class="badge badge-safe">SAFE</span>'
        else:
            return '<span class="badge badge-info">INFO</span>'

    # Risk level badge
    r_lvl = risk["risk_level"]
    if r_lvl == "CRITICAL":
        risk_badge_html = '<span class="risk-badge risk-badge-critical">CRITICAL THREAT</span>'
    elif r_lvl == "HIGH":
        risk_badge_html = '<span class="risk-badge risk-badge-high">HIGH RISK</span>'
    elif r_lvl == "MEDIUM":
        risk_badge_html = '<span class="risk-badge risk-badge-medium">MEDIUM RISK</span>'
    elif r_lvl == "LOW":
        risk_badge_html = '<span class="risk-badge risk-badge-low">LOW RISK</span>'
    elif r_lvl == "SAFE":
        risk_badge_html = '<span class="risk-badge risk-badge-safe">SAFE / CLEAN</span>'
    else:
        risk_badge_html = '<span class="risk-badge risk-badge-info">INCONCLUSIVE</span>'

    # Build Technical Findings Table Rows
    findings_rows = []
    for f in unique_findings:
        findings_rows.append(f"""
        <tr>
            <td class="mono">{html.escape(f['fingerprint'])}</td>
            <td><span class="module-tag">{html.escape(f['module'].upper())}</span></td>
            <td class="mono" style="font-weight:600;color:#F1F5F9;">{html.escape(f['indicator'])}</td>
            <td>{html.escape(f['description'])}</td>
            <td>{sev_badge(f['severity'])}</td>
            <td><span class="badge badge-muted">{html.escape(f['confidence'])}</span></td>
            <td class="text-center">{f['observation_count']}</td>
        </tr>
        """)
    findings_table_html = "".join(findings_rows) if findings_rows else "<tr><td colspan='7' class='text-center muted'>No findings recorded in investigation.</td></tr>"

    # Build Detailed Finding Cards
    detailed_cards = []
    for idx, f in enumerate(unique_findings, start=1):
        detailed_cards.append(f"""
        <div class="finding-card">
            <div class="finding-header">
                <div class="finding-title-group">
                    <span class="finding-index">FINDING #{idx:02d}</span>
                    <h4 class="finding-title">{html.escape(f['indicator'])} ({html.escape(f['module'].upper())})</h4>
                </div>
                <div class="finding-badge-group">
                    {sev_badge(f['severity'])}
                    <span class="badge badge-muted">Confidence: {html.escape(f['confidence'])}</span>
                    <span class="badge badge-muted">Status: {html.escape(f['status'])}</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-grid">
                    <div>
                        <div class="meta-label">Finding Overview</div>
                        <p class="meta-val">{html.escape(f['description'])}</p>
                    </div>
                    <div>
                        <div class="meta-label">Source & Timeline</div>
                        <p class="meta-val mono" style="font-size:11px;">
                            Sources: {', '.join(f['sources'])}<br>
                            First Observed: {html.escape(f['first_seen'])}<br>
                            Last Observed: {html.escape(f['last_seen'])} ({f['observation_count']} raw hits)
                        </p>
                    </div>
                </div>
                <div style="margin-top:12px;">
                    <div class="meta-label">Recommended Remediation</div>
                    <div class="remediation-box">{html.escape(f['remediation'])}</div>
                </div>
            </div>
        </div>
        """)
    detailed_findings_html = "".join(detailed_cards) if detailed_cards else "<p class='muted'>No individual finding cards generated.</p>"

    # Build Scoring Breakdown Rows
    score_rows = []
    for fac in scoring_factors:
        score_rows.append(f"""
        <tr>
            <td style="font-weight:600;color:#F1F5F9;">{html.escape(fac['name'])}</td>
            <td><span class="module-tag">{html.escape(fac['module'].upper())}</span></td>
            <td class="mono">{html.escape(fac['indicator'])}</td>
            <td>{html.escape(fac['raw_metric'])}</td>
            <td class="text-right mono text-signal">+{fac['contribution']:.2f}</td>
            <td>{sev_badge(fac['severity'])}</td>
            <td><span class="badge badge-muted">{html.escape(fac['confidence'])}</span></td>
        </tr>
        """)
    score_table_html = "".join(score_rows) if score_rows else "<tr><td colspan='7' class='text-center muted'>No risk penalty factors applied. Base score 0.0.</td></tr>"

    # Build IOC Correlation Rows
    corr_rows = []
    for rel in correlations:
        corr_rows.append(f"""
        <tr>
            <td class="mono font-bold" style="color:#06B6D4;">{html.escape(rel['source'])} <span class="muted text-xs">({rel['source_type']})</span></td>
            <td class="text-center"><span class="rel-tag">{html.escape(rel['relationship'])}</span></td>
            <td class="mono font-bold" style="color:#10B981;">{html.escape(rel['target'])} <span class="muted text-xs">({rel['target_type']})</span></td>
            <td>{html.escape(rel['evidence'])}</td>
            <td><span class="badge badge-muted">{html.escape(rel['confidence'])}</span></td>
        </tr>
        """)
    corr_table_html = "".join(corr_rows) if corr_rows else "<tr><td colspan='5' class='text-center muted'>No cross-indicator technical relationships identified.</td></tr>"

    # Build MITRE ATT&CK Rows
    mitre_rows = []
    for m in mitre_list:
        is_tool = m.get("mapping_type") == "TOOL_COLLECTION_ACTIVITY"
        type_badge = '<span class="badge badge-tool">OSINT Recon Activity</span>' if is_tool else '<span class="badge badge-adversary">Observed Threat Action</span>'
        mitre_rows.append(f"""
        <tr>
            <td class="mono font-bold text-signal">{html.escape(m['technique_id'])}</td>
            <td style="color:#CBD5E1;">{html.escape(m['tactic'])}</td>
            <td style="font-weight:600;color:#F8FAFC;">{html.escape(m['technique_name'])}</td>
            <td>{type_badge}</td>
            <td style="font-size:11px;color:#94A3B8;">{html.escape(m.get('evidence', ''))}</td>
            <td><span class="badge badge-muted">{html.escape(m.get('confidence', 'HIGH'))}</span></td>
        </tr>
        """)
    mitre_table_html = "".join(mitre_rows) if mitre_rows else "<tr><td colspan='6' class='text-center muted'>No MITRE techniques mapped.</td></tr>"

    # Build Recommendations List
    recs_html_list = []
    for r in recommendations:
        recs_html_list.append(f"""
        <div class="rec-item">
            <div class="rec-header">
                <span class="rec-priority rec-p-{r['priority'].lower()}">{html.escape(r['priority'])} PRIORITY</span>
                <span class="rec-title">{html.escape(r['title'])}</span>
            </div>
            <p class="rec-action">{html.escape(r['action'])}</p>
            <div class="rec-meta">Target: <code class="mono">{html.escape(r['target'])}</code> • Rationale: {html.escape(r['rationale'])}</div>
        </div>
        """)
    recs_section_html = "".join(recs_html_list) if recs_html_list else "<p class='muted'>No active recommendations. Baseline maintenance only.</p>"

    # Module Intelligence Subsections (Conditional Rendering)
    has_domain = len(mod_intel.get("domain", [])) > 0
    has_ip = len(mod_intel.get("ip", [])) > 0
    has_email = len(mod_intel.get("email", [])) > 0
    has_user = len(mod_intel.get("username", [])) > 0
    has_file = len(mod_intel.get("file", [])) > 0
    has_threat = len(mod_intel.get("threat_intel", [])) > 0

    # Table of contents items
    toc_items = [
        ("sec-cover", "1. Document Metadata & Authorization"),
        ("sec-exec", "2. Executive Summary & Narrative"),
        ("sec-scope", "3. Investigation Scope & Objectives"),
        ("sec-method", "4. Methodology & Tool Sources"),
        ("sec-stats", "5. Investigation Statistics"),
        ("sec-risk", "6. Risk Assessment & Factor Breakdown"),
        ("sec-findings", "7. Deduplicated Technical Findings"),
        ("sec-cards", "8. Detailed Finding Breakdowns"),
    ]
    if has_domain: toc_items.append(("sec-domain", "9. Domain Infrastructure Intelligence"))
    if has_ip: toc_items.append(("sec-ip", "10. IP Network & Host Intelligence"))
    if has_email: toc_items.append(("sec-email", "11. Email & Credential Breach Recon"))
    if has_user: toc_items.append(("sec-user", "12. Username & Platform Footprint"))
    if has_file: toc_items.append(("sec-file", "13. File Forensics & Artifact Hashes"))
    if has_threat: toc_items.append(("sec-threat", "14. Threat Intelligence Feeds"))
    toc_items.extend([
        ("sec-corr", "15. IOC Correlations & Relationships"),
        ("sec-mitre", "16. MITRE ATT&CK Framework Mapping"),
        ("sec-surface", "17. Potential Attack Surface Analysis"),
        ("sec-recs", "18. Prioritized Recommendations & Remediation"),
        ("sec-limits", "19. Investigation Limitations & Caveats"),
        ("sec-evidence", "20. Registered Indicators of Compromise"),
        ("sec-raw", "21. Appendix – Raw Technical Audit Log"),
    ])

    toc_links_html = "".join(f'<li><a href="#{tid}">{title}</a></li>' for tid, title in toc_items)

    html_report = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT-X Intelligence Briefing - {html.escape(meta['title'])}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-base: #0B1120;
            --bg-surface: #0F172A;
            --bg-card: #1E293B;
            --border: #334155;
            --border-light: #475569;
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --text-muted: #64748B;
            --signal: #10B981;
            --signal-glow: rgba(16, 185, 129, 0.15);
            --cyan: #06B6D4;
            --amber: #F59E0B;
            --red: #EF4444;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 13px;
            line-height: 1.6;
            padding: 0;
            margin: 0;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }}

        .mono {{
            font-family: 'JetBrains Mono', 'Courier New', monospace;
        }}

        /* Print Specific Styles */
        @media print {{
            @page {{
                size: A4;
                margin: 12mm 15mm 15mm 15mm;
            }}
            body {{
                background-color: #FFFFFF !important;
                color: #0F172A !important;
                font-size: 10.5pt;
            }}
            .no-print {{
                display: none !important;
            }}
            .report-container {{
                max-width: 100% !important;
                padding: 0 !important;
            }}
            .page-break {{
                page-break-before: always;
            }}
            .card, .finding-card, table {{
                page-break-inside: avoid;
                background-color: #FFFFFF !important;
                border: 1px solid #CBD5E1 !important;
                color: #0F172A !important;
            }}
            th {{
                background-color: #F1F5F9 !important;
                color: #0F172A !important;
            }}
            td {{
                border-bottom: 1px solid #E2E8F0 !important;
                color: #0F172A !important;
            }}
            .text-signal {{
                color: #059669 !important;
            }}
            .badge {{
                border: 1px solid #94A3B8 !important;
            }}
            thead {{
                display: table-header-group;
            }}
        }}

        .report-container {{
            max-width: 1160px;
            margin: 0 auto;
            padding: 30px 24px 60px 24px;
        }}

        /* Top Action Bar */
        .action-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            padding: 12px 20px;
            border-radius: 8px;
            margin-bottom: 24px;
        }}
        .brand-badge {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
            font-size: 14px;
            color: var(--signal);
            font-family: 'JetBrains Mono', monospace;
        }}
        .brand-badge span.pulse {{
            width: 8px;
            height: 8px;
            background: var(--signal);
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 10px var(--signal);
        }}
        .btn-print {{
            background: var(--signal);
            color: #0B1120;
            border: none;
            padding: 8px 16px;
            font-size: 12px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .btn-print:hover {{
            background: #059669;
            color: #FFFFFF;
        }}

        /* Cover & Header */
        .cover-box {{
            background: linear-gradient(135deg, var(--bg-surface) 0%, #131E35 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px;
            margin-bottom: 24px;
            position: relative;
            overflow: hidden;
        }}
        .cover-box::before {{
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--signal), var(--cyan));
        }}
        .tlp-banner {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            font-weight: 800;
            letter-spacing: 1px;
            margin-bottom: 16px;
            text-transform: uppercase;
            background: rgba(245, 158, 11, 0.15);
            color: var(--amber);
            border: 1px solid rgba(245, 158, 11, 0.4);
        }}
        .report-title {{
            font-size: 26px;
            font-weight: 800;
            color: #FFFFFF;
            letter-spacing: -0.5px;
            margin-bottom: 8px;
        }}
        .report-subtitle {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 24px;
            max-width: 800px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            background: rgba(11, 17, 32, 0.6);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
        }}
        .meta-label {{
            font-size: 10px;
            text-transform: uppercase;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            margin-bottom: 4px;
            letter-spacing: 0.5px;
        }}
        .meta-val {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-primary);
        }}

        /* Table of Contents */
        .toc-box {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 24px;
        }}
        .toc-title {{
            font-size: 12px;
            font-weight: 700;
            color: var(--signal);
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            margin-bottom: 12px;
        }}
        .toc-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 8px 16px;
            list-style: none;
            padding-left: 0;
        }}
        .toc-grid li a {{
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 12px;
            transition: color 0.15s ease;
        }}
        .toc-grid li a:hover {{
            color: var(--signal);
            text-decoration: underline;
        }}

        /* Section Cards */
        .section-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section-header {{
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .section-title {{
            font-size: 15px;
            font-weight: 700;
            color: #FFFFFF;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .section-title span.tag {{
            color: var(--signal);
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
        }}
        .section-desc {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 2px;
        }}

        /* Stats Tiles */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 14px;
            margin-bottom: 18px;
        }}
        .stat-tile {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
        }}
        .stat-num {{
            font-size: 24px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            color: #FFFFFF;
            line-height: 1.2;
        }}
        .stat-label {{
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 4px;
            text-transform: uppercase;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(245, 158, 11, 0.2); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.4); }}
        .badge-medium {{ background: rgba(59, 130, 246, 0.2); color: #60A5FA; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-low {{ background: rgba(148, 163, 184, 0.15); color: #CBD5E1; border: 1px solid rgba(148, 163, 184, 0.3); }}
        .badge-info {{ background: rgba(14, 165, 233, 0.15); color: #38BDF8; border: 1px solid rgba(14, 165, 233, 0.3); }}
        .badge-safe {{ background: rgba(16, 185, 129, 0.2); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .badge-muted {{ background: #1E293B; color: #94A3B8; border: 1px solid #334155; }}
        .badge-tool {{ background: rgba(6, 182, 212, 0.15); color: var(--cyan); border: 1px solid rgba(6, 182, 212, 0.3); }}
        .badge-adversary {{ background: rgba(239, 68, 68, 0.2); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.4); }}

        .risk-badge {{
            display: inline-block;
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: 1px;
        }}
        .risk-badge-critical {{ background: #7F1D1D; color: #FEE2E2; border: 1px solid #EF4444; }}
        .risk-badge-high {{ background: #78350F; color: #FEF3C7; border: 1px solid #F59E0B; }}
        .risk-badge-medium {{ background: #1E3A8A; color: #DBEAFE; border: 1px solid #3B82F6; }}
        .risk-badge-low {{ background: #1E293B; color: #E2E8F0; border: 1px solid #64748B; }}
        .risk-badge-safe {{ background: #064E3B; color: #D1FAE5; border: 1px solid #10B981; }}
        .risk-badge-info {{ background: #1E293B; color: #94A3B8; border: 1px solid #475569; }}

        .module-tag {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            padding: 2px 6px;
            background: #1E293B;
            border-radius: 3px;
            color: #CBD5E1;
            font-weight: 600;
        }}
        .rel-tag {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            padding: 2px 6px;
            background: rgba(6, 182, 212, 0.15);
            border: 1px solid rgba(6, 182, 212, 0.3);
            border-radius: 3px;
            color: var(--cyan);
            font-weight: 700;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 10px;
        }}
        th {{
            background: #0B1120;
            color: #94A3B8;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: 0.5px;
            padding: 10px 12px;
            border: 1px solid var(--border);
            text-align: left;
        }}
        td {{
            padding: 10px 12px;
            border: 1px solid var(--border);
            color: #E2E8F0;
            vertical-align: middle;
        }}
        tr:nth-child(even) td {{
            background: rgba(15, 23, 42, 0.4);
        }}
        .text-center {{ text-align: center; }}
        .text-right {{ text-align: right; }}
        .text-signal {{ color: var(--signal); }}
        .muted {{ color: var(--text-muted); }}

        /* Finding Cards */
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 14px;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 1px solid rgba(51, 65, 85, 0.5);
            padding-bottom: 10px;
            margin-bottom: 12px;
            gap: 12px;
        }}
        .finding-index {{
            font-size: 10px;
            font-family: 'JetBrains Mono', monospace;
            color: var(--signal);
            font-weight: 700;
            display: block;
            margin-bottom: 2px;
        }}
        .finding-title {{
            font-size: 14px;
            font-weight: 700;
            color: #FFFFFF;
        }}
        .finding-badge-group {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
        }}
        .finding-grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 14px;
        }}
        .remediation-box {{
            background: rgba(16, 185, 129, 0.08);
            border-left: 3px solid var(--signal);
            padding: 8px 12px;
            border-radius: 0 4px 4px 0;
            font-size: 12px;
            color: #E2E8F0;
        }}

        /* Recommendations */
        .rec-item {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
        }}
        .rec-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 6px;
        }}
        .rec-priority {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 10px;
            font-weight: 800;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        .rec-p-critical {{ background: #7F1D1D; color: #FEE2E2; }}
        .rec-p-high {{ background: #78350F; color: #FEF3C7; }}
        .rec-p-medium {{ background: #1E3A8A; color: #DBEAFE; }}
        .rec-p-low {{ background: #1E293B; color: #CBD5E1; }}
        .rec-title {{
            font-weight: 700;
            font-size: 13px;
            color: #FFFFFF;
        }}
        .rec-action {{
            color: #CBD5E1;
            font-size: 12px;
            margin-bottom: 6px;
        }}
        .rec-meta {{
            font-size: 11px;
            color: var(--text-muted);
        }}

        /* Narrative typography */
        .narrative-content p {{
            margin-bottom: 10px;
            color: #CBD5E1;
            line-height: 1.6;
        }}
        .narrative-content strong {{
            color: #FFFFFF;
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Top Action Bar (hidden on print) -->
        <div class="action-bar no-print">
            <div class="brand-badge">
                <span class="pulse"></span>
                <span>OSINT-X INTELLIGENCE SYSTEM</span>
            </div>
            <div style="display:flex;gap:10px;align-items:center;">
                <span style="font-size:11px;color:var(--text-muted);">Case #{html.escape(meta['case_id'])}</span>
                <button class="btn-print" onclick="window.print()">Print / Export PDF</button>
            </div>
        </div>

        <!-- 1. COVER PAGE / METADATA -->
        <div id="sec-cover" class="cover-box">
            <div class="tlp-banner">{html.escape(meta['classification'])} • RESTRICTED ACCESS</div>
            <h1 class="report-title">{html.escape(meta['title'])}</h1>
            <p class="report-subtitle">{html.escape(meta['description'])}</p>

            <div class="meta-grid">
                <div>
                    <div class="meta-label">Primary Investigation Target</div>
                    <div class="meta-val mono" style="color:var(--signal);">{html.escape(meta['target'])}</div>
                </div>
                <div>
                    <div class="meta-label">Case Identifier</div>
                    <div class="meta-val mono">#{html.escape(meta['case_id'])} ({html.escape(meta['investigation_id'][:12])}...)</div>
                </div>
                <div>
                    <div class="meta-label">Investigation Status</div>
                    <div class="meta-val">{html.escape(meta['status'])}</div>
                </div>
                <div>
                    <div class="meta-label">Lead Intelligence Analyst</div>
                    <div class="meta-val">{html.escape(meta['analyst'])}</div>
                </div>
                <div>
                    <div class="meta-label">Report Generation Date</div>
                    <div class="meta-val mono">{html.escape(meta['generated_at'][:19].replace('T', ' '))} UTC</div>
                </div>
                <div>
                    <div class="meta-label">Report Version & Engine</div>
                    <div class="meta-val mono">v{html.escape(meta['report_version'])} (Deterministic Core)</div>
                </div>
            </div>
        </div>

        <!-- TABLE OF CONTENTS -->
        <div class="toc-box no-print">
            <div class="toc-title">Table of Contents</div>
            <ul class="toc-grid">
                {toc_links_html}
            </ul>
        </div>

        <!-- 2. EXECUTIVE SUMMARY -->
        <div id="sec-exec" class="section-card page-break">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">02</span> Executive Intelligence Summary</h3>
                    <div class="section-desc">High-level threat assessment synthesized from multi-feed deterministic findings</div>
                </div>
                <div>{risk_badge_html}</div>
            </div>

            <div class="stats-grid">
                <div class="stat-tile">
                    <div class="stat-num text-signal">{risk['risk_score']} / 10</div>
                    <div class="stat-label">Calculated Threat Score</div>
                </div>
                <div class="stat-tile">
                    <div class="stat-num">{html.escape(exec_sum['overall_risk_level'])}</div>
                    <div class="stat-label">Risk Severity Tier</div>
                </div>
                <div class="stat-tile">
                    <div class="stat-num">{html.escape(exec_sum['confidence'])}</div>
                    <div class="stat-label">Analytical Confidence</div>
                </div>
                <div class="stat-tile">
                    <div class="stat-num">{html.escape(exec_sum['organizational_impact'])}</div>
                    <div class="stat-label">Organizational Risk</div>
                </div>
            </div>

            <div class="narrative-content" style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:20px;margin-top:12px;">
                {exec_sum['narrative_html'] if exec_sum['narrative_html'] else f"<p>{html.escape(exec_sum['narrative'])}</p>"}
            </div>
        </div>

        <!-- 3. INVESTIGATION SCOPE & OBJECTIVES -->
        <div id="sec-scope" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">03</span> Investigation Scope & Objectives</h3>
                    <div class="section-desc">Defines targets, authorization boundaries, and core investigative intent</div>
                </div>
            </div>
            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:16px;">
                <div style="background:var(--bg-card);padding:16px;border-radius:6px;border:1px solid var(--border);">
                    <div class="meta-label">Authorized Scope</div>
                    <p style="color:#CBD5E1;font-size:12px;">{html.escape(rep['investigation_scope']['authorized_scope'])}</p>
                </div>
                <div style="background:var(--bg-card);padding:16px;border-radius:6px;border:1px solid var(--border);">
                    <div class="meta-label">Primary Investigation Objectives</div>
                    <p style="color:#CBD5E1;font-size:12px;">Identify internet-exposed infrastructure, verify active threat intelligence flags, uncover compromised credentials, and correlate cross-platform identities.</p>
                </div>
            </div>
        </div>

        <!-- 4. METHODOLOGY & TOOLS -->
        <div id="sec-method" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">04</span> Investigation Methodology & Tool Sources</h3>
                    <div class="section-desc">Framework standards and external intelligence feeds utilized in this assessment</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Intelligence Source / Tool</th>
                        <th>Investigative Function</th>
                        <th>Classification</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f"<tr><td class='font-bold' style='color:#F1F5F9;'>{html.escape(t['name'])}</td><td>{html.escape(t['role'])}</td><td><span class='badge badge-muted'>{html.escape(t['type'])}</span></td></tr>" for t in rep['tools_and_sources'])}
                </tbody>
            </table>
        </div>

        <!-- 5. INVESTIGATION STATISTICS -->
        <div id="sec-stats" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">05</span> Investigation Telemetry & Deduplication Statistics</h3>
                    <div class="section-desc">Metrics comparing raw probe hits against unique normalized findings</div>
                </div>
            </div>
            <div class="stats-grid">
                <div class="stat-tile">
                    <div class="stat-num">{stats['total_raw_observations']}</div>
                    <div class="stat-label">Total Raw Observations</div>
                </div>
                <div class="stat-tile">
                    <div class="stat-num text-signal">{stats['total_unique_findings']}</div>
                    <div class="stat-label">Unique Findings</div>
                </div>
                <div class="stat-tile">
                    <div class="stat-num" style="color:var(--cyan);">{stats['duplicate_observations_merged']}</div>
                    <div class="stat-label">Duplicates Merged</div>
                </div>
                <div class="stat-tile">
                    <div class="stat-num" style="color:var(--amber);">{stats['total_correlations_identified']}</div>
                    <div class="stat-label">Indicator Links</div>
                </div>
            </div>
            <div style="background:var(--bg-card);padding:14px;border-radius:6px;border:1px solid var(--border);display:flex;justify-content:space-around;flex-wrap:wrap;gap:10px;">
                <span>Critical: <strong style="color:#F87171;">{stats['severity_distribution']['CRITICAL']}</strong></span>
                <span>High: <strong style="color:#FBBF24;">{stats['severity_distribution']['HIGH']}</strong></span>
                <span>Medium: <strong style="color:#60A5FA;">{stats['severity_distribution']['MEDIUM']}</strong></span>
                <span>Low: <strong style="color:#CBD5E1;">{stats['severity_distribution']['LOW']}</strong></span>
                <span>Info: <strong style="color:#38BDF8;">{stats['severity_distribution']['INFO']}</strong></span>
            </div>
        </div>

        <!-- 6. RISK ASSESSMENT & BREAKDOWN -->
        <div id="sec-risk" class="section-card page-break">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">06</span> Risk Assessment & Mathematical Scoring Breakdown</h3>
                    <div class="section-desc">Deterministic point contribution for each verified risk factor</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Risk Factor Name</th>
                        <th>Module</th>
                        <th>Indicator</th>
                        <th>Metric Evidence</th>
                        <th class="text-right">Score Weight</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {score_table_html}
                </tbody>
            </table>
            <div style="margin-top:16px;background:var(--bg-card);padding:16px;border-radius:6px;border:1px solid var(--border);">
                <div class="meta-label">Analytical Risk Explanation</div>
                <div class="narrative-content" style="font-size:12px;">
                    {risk.get('explanation_html') or html.escape(risk.get('explanation', ''))}
                </div>
            </div>
        </div>

        <!-- 7. TECHNICAL FINDINGS TABLE -->
        <div id="sec-findings" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">07</span> Deduplicated Technical Findings Table</h3>
                    <div class="section-desc">Canonical inventory of unique findings across all scan modules</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Fingerprint</th>
                        <th>Module</th>
                        <th>Indicator</th>
                        <th>Description</th>
                        <th>Severity</th>
                        <th>Confidence</th>
                        <th>Observations</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_table_html}
                </tbody>
            </table>
        </div>

        <!-- 8. DETAILED FINDING BREAKDOWNS -->
        <div id="sec-cards" class="section-card page-break">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">08</span> Detailed Technical Findings</h3>
                    <div class="section-desc">Individual finding analysis with evidence, impact, and actionable remediation</div>
                </div>
            </div>
            {detailed_findings_html}
        </div>

        <!-- MODULE INTELLIGENCE SECTIONS (Rendered only if relevant data exists) -->
        {f'''
        <!-- 9. DOMAIN INTELLIGENCE -->
        <div id="sec-domain" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">09</span> Domain Infrastructure Intelligence</h3>
                    <div class="section-desc">DNS zone topology, WHOIS ownership, and SSL/TLS certificate evaluation</div>
                </div>
            </div>
            {"".join(f"""
            <div class="finding-card">
                <h4 style="color:#10B981;font-weight:700;margin-bottom:8px;">Domain: {html.escape(d.get('target', ''))}</h4>
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:12px;margin-bottom:12px;">
                    <div><span class="meta-label">Registrar:</span> <span class="meta-val">{(d.get('whois') or {}).get('registrar', 'N/A')}</span></div>
                    <div><span class="meta-label">SSL Issuer:</span> <span class="meta-val">{(d.get('ssl') or {}).get('issuer', 'N/A')}</span></div>
                    <div><span class="meta-label">SSL Valid:</span> <span class="meta-val">{"Valid" if (d.get('ssl') or {}).get('valid') else "Invalid/Expired"}</span></div>
                    <div><span class="meta-label">Security Header Grade:</span> <span class="meta-val">{(d.get('http') or {}).get('security_score', 'N/A')}</span></div>
                </div>
                <div><span class="meta-label">Subdomains Discovered ({len(d.get('subdomains', []))}):</span>
                <p class="mono" style="font-size:11px;color:#94A3B8;word-break:break-all;">{', '.join(d.get('subdomains', [])[:15]) if d.get('subdomains') else "No active subdomains mapped."}</p></div>
            </div>
            """ for d in mod_intel.get("domain", []))}
        </div>
        ''' if has_domain else ''}

        {f'''
        <!-- 10. IP INTELLIGENCE -->
        <div id="sec-ip" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">10</span> IP Network & Host Intelligence</h3>
                    <div class="section-desc">BGP routing, geolocation, and perimeter listening port exposures</div>
                </div>
            </div>
            {"".join(f"""
            <div class="finding-card">
                <h4 style="color:#06B6D4;font-weight:700;margin-bottom:8px;">Host IP: {html.escape(ip.get('target', ''))}</h4>
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:12px;margin-bottom:12px;">
                    <div><span class="meta-label">Country / Region:</span> <span class="meta-val">{(ip.get('geoip') or {}).get('country', 'N/A')}, {(ip.get('geoip') or {}).get('city', 'N/A')}</span></div>
                    <div><span class="meta-label">ISP / Org:</span> <span class="meta-val">{(ip.get('geoip') or {}).get('isp', 'N/A')}</span></div>
                    <div><span class="meta-label">ASN:</span> <span class="meta-val mono">{(ip.get('geoip') or {}).get('asn', 'N/A')}</span></div>
                    <div><span class="meta-label">Open Ports:</span> <span class="meta-val mono text-signal">{', '.join(str(p) for p in ip.get('open_ports', [])) if ip.get('open_ports') else "None detected"}</span></div>
                </div>
            </div>
            """ for ip in mod_intel.get("ip", []))}
        </div>
        ''' if has_ip else ''}

        {f'''
        <!-- 11. EMAIL INTELLIGENCE -->
        <div id="sec-email" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">11</span> Email & Credential Breach Reconnaissance</h3>
                    <div class="section-desc">Mail spoofing posture (SPF/DMARC) and public credential breach exposures</div>
                </div>
            </div>
            {"".join(f"""
            <div class="finding-card">
                <h4 style="color:#FBBF24;font-weight:700;margin-bottom:8px;">Email Target: {html.escape(em.get('target', ''))}</h4>
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:12px;margin-bottom:12px;">
                    <div><span class="meta-label">Disposable / Burner:</span> <span class="meta-val">{"YES (Disposable)" if em.get('is_disposable') else "NO (Standard)"}</span></div>
                    <div><span class="meta-label">SPF Record:</span> <span class="meta-val">{"Published" if (em.get('dns_security') or {}).get('has_spf') else "Missing"}</span></div>
                    <div><span class="meta-label">DMARC Record:</span> <span class="meta-val">{"Enforced" if (em.get('dns_security') or {}).get('has_dmarc') else "Missing"}</span></div>
                    <div><span class="meta-label">Breach Count:</span> <span class="meta-val font-bold text-signal">{(em.get('breaches') or {}).get('total_breaches', 0) if isinstance(em.get('breaches'), dict) else len(em.get('breaches') or [])} incidents</span></div>
                </div>
            </div>
            """ for em in mod_intel.get("email", []))}
        </div>
        ''' if has_email else ''}

        {f'''
        <!-- 12. USERNAME INTELLIGENCE -->
        <div id="sec-user" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">12</span> Username & Online Identity Footprint</h3>
                    <div class="section-desc">Public account correlation across social networks and developer platforms</div>
                </div>
            </div>
            {"".join(f"""
            <div class="finding-card">
                <h4 style="color:#F8FAFC;font-weight:700;margin-bottom:8px;">Handle: @{html.escape(u.get('target', ''))}</h4>
                <p style="font-size:12px;color:#94A3B8;margin-bottom:8px;">Verified accounts found on {(u.get('summary') or {}).get('total_found', 0)} of {(u.get('summary') or {}).get('total_checked', 15)} probed platforms:</p>
                <div style="display:flex;gap:8px;flex-wrap:wrap;">
                    {"".join(f'<span class="badge badge-safe">{html.escape(p)}</span>' for p in (u.get('summary') or {}).get('found_platforms', [])) if (u.get('summary') or {}).get('found_platforms') else "<span class='muted'>No active platform profiles discovered.</span>"}
                </div>
            </div>
            """ for u in mod_intel.get("username", []))}
        </div>
        ''' if has_user else ''}

        {f'''
        <!-- 13. FILE INTELLIGENCE -->
        <div id="sec-file" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">13</span> File Forensics & Artifact Hashes</h3>
                    <div class="section-desc">Cryptographic digest identification and embedded metadata extraction</div>
                </div>
            </div>
            {"".join(f"""
            <div class="finding-card">
                <h4 style="color:#CBD5E1;font-weight:700;margin-bottom:8px;">File Artifact: {html.escape(fi.get('target', ''))}</h4>
                <div class="mono" style="font-size:11px;background:#0B1120;padding:10px;border-radius:4px;border:1px solid var(--border);">
                    SHA-256: {(fi.get('hashes') or {}).get('sha256', 'N/A')}<br>
                    MD5: {(fi.get('hashes') or {}).get('md5', 'N/A')}
                </div>
            </div>
            """ for fi in mod_intel.get("file", []))}
        </div>
        ''' if has_file else ''}

        {f'''
        <!-- 14. THREAT INTEL -->
        <div id="sec-threat" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">14</span> Multi-Vendor Threat Intelligence Feeds</h3>
                    <div class="section-desc">Anti-virus engine scores, blacklist reports, and abuse telemetry</div>
                </div>
            </div>
            {"".join(f"""
            <div class="finding-card">
                <h4 style="color:#EF4444;font-weight:700;margin-bottom:8px;">Indicator: {html.escape(th.get('target', ''))}</h4>
                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:12px;">
                    <div><span class="meta-label">VirusTotal Malicious Detections:</span> <span class="meta-val font-bold text-signal">{(th.get('summary') or {}).get('vt_malicious_count', 0)} engines</span></div>
                    <div><span class="meta-label">AbuseIPDB Confidence:</span> <span class="meta-val font-bold">{(th.get('summary') or {}).get('abuse_confidence', 0)}%</span></div>
                    <div><span class="meta-label">Threat Classification:</span> <span class="meta-val">{(th.get('summary') or {}).get('threat_level', 'Clean')}</span></div>
                </div>
            </div>
            """ for th in mod_intel.get("threat_intel", []))}
        </div>
        ''' if has_threat else ''}

        <!-- 15. IOC CORRELATIONS -->
        <div id="sec-corr" class="section-card page-break">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">15</span> IOC Correlation & Infrastructure Relationships</h3>
                    <div class="section-desc">Evidence-backed connections between domains, IPs, subdomains, and identities</div>
                </div>
                <div><span class="badge badge-muted">Total Links: {len(correlations)}</span></div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Source Indicator</th>
                        <th class="text-center">Relationship Type</th>
                        <th>Target Indicator</th>
                        <th>Technical Evidence</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {corr_table_html}
                </tbody>
            </table>
        </div>

        <!-- 16. MITRE ATT&CK MAPPING -->
        <div id="sec-mitre" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">16</span> MITRE ATT&CK Enterprise Matrix Mapping</h3>
                    <div class="section-desc">Distinguishes OSINT-X automated collection actions from observed adversary techniques</div>
                </div>
                <div>
                    <span class="badge badge-tool">{rep['mitre_attack']['tool_reconnaissance_count']} Tool Actions</span>
                    <span class="badge badge-adversary">{rep['mitre_attack']['adversary_behavior_count']} Threat Behaviors</span>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Technique ID</th>
                        <th>Tactic</th>
                        <th>Technique Name</th>
                        <th>Mapping Type</th>
                        <th>Evidence / Rationale</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {mitre_table_html}
                </tbody>
            </table>
        </div>

        <!-- 17. ATTACK SURFACE ANALYSIS -->
        <div id="sec-surface" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">17</span> Potential Attack Surface Synthesis</h3>
                    <div class="section-desc">Holistic evaluation of perimeter exposure vectors and security gaps</div>
                </div>
            </div>
            <div style="background:var(--bg-card);padding:18px;border-radius:8px;border:1px solid var(--border);">
                <p style="font-size:12px;color:#CBD5E1;line-height:1.6;">{html.escape(attack_surface)}</p>
            </div>
        </div>

        <!-- 18. RECOMMENDATIONS -->
        <div id="sec-recs" class="section-card page-break">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">18</span> Prioritized Remediation Recommendations</h3>
                    <div class="section-desc">Actionable defensive measures prioritized by risk impact and exploitability</div>
                </div>
            </div>
            {recs_section_html}
        </div>

        <!-- 19. INVESTIGATION LIMITATIONS -->
        <div id="sec-limits" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">19</span> Investigation Limitations & Scan Boundaries</h3>
                    <div class="section-desc">Caveats, unconfigured API feeds, and technical boundaries governing this report</div>
                </div>
            </div>
            <ul style="margin:8px 0 8px 20px;padding-left:10px;color:#CBD5E1;font-size:12px;line-height:1.8;">
                {"".join(f"<li>{html.escape(lim)}</li>" for lim in limitations)}
            </ul>
        </div>

        <!-- 20. REGISTERED IOCs -->
        <div id="sec-evidence" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">20</span> Registered Indicators of Compromise (IOCs)</h3>
                    <div class="section-desc">Inventory of technical indicators tracked within the investigation database</div>
                </div>
                <div><span class="badge badge-muted">Total: {len(iocs_list)}</span></div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Indicator Value</th>
                        <th>Type</th>
                        <th>Source Provider</th>
                        <th>Reputation</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f"<tr><td class='mono font-bold' style='color:#F1F5F9;'>{html.escape(i['value'])}</td><td><span class='badge badge-muted'>{html.escape(i['type'])}</span></td><td>{html.escape(i['source'])}</td><td>{i['reputation_score']:.1f}</td><td class='mono muted' style='font-size:11px;'>{html.escape(str(i['first_seen'])[:19])}</td></tr>" for i in iocs_list[:25]) if iocs_list else "<tr><td colspan='5' class='text-center muted'>No IOCs registered.</td></tr>"}
                </tbody>
            </table>
        </div>

        <!-- 21. APPENDIX: RAW OBSERVATIONS -->
        <div id="sec-raw" class="section-card">
            <div class="section-header">
                <div>
                    <h3 class="section-title"><span class="tag">21</span> Appendix – Raw Technical Observation Audit Log</h3>
                    <div class="section-desc">Immutable log of raw scanner execution records for forensic verification</div>
                </div>
                <div><span class="badge badge-muted">Total Observations: {len(raw_obs)}</span></div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Observation ID</th>
                        <th>Module</th>
                        <th>Scan Type</th>
                        <th>Target Indicator</th>
                        <th>Timestamp (UTC)</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(f"<tr><td class='mono muted' style='font-size:11px;'>{html.escape(r['id'][:12])}...</td><td><span class='module-tag'>{html.escape(r['module'])}</span></td><td>{html.escape(r['type'])}</td><td class='mono'>{html.escape(r['target'])}</td><td class='mono muted' style='font-size:11px;'>{html.escape(str(r['created_at'])[:19])}</td></tr>" for r in raw_obs[:30]) if raw_obs else "<tr><td colspan='5' class='text-center muted'>No raw observation records.</td></tr>"}
                </tbody>
            </table>
        </div>

        <!-- FOOTER -->
        <div style="text-align:center;font-size:11px;color:var(--text-muted);margin-top:40px;border-top:1px solid var(--border);padding-top:20px;">
            <p><strong>OSINT-X Cybersecurity Intelligence Platform</strong> • Automated Intelligence Briefing</p>
            <p style="margin-top:4px;">Classification: {html.escape(meta['classification'])} • Authorized Recipient Use Only • Document Hash ID: #{html.escape(meta['case_id'])}</p>
        </div>
    </div>
</body>
</html>"""
    return html_report


def save_report_record(
    db: Session,
    investigation_id: str,
    report_type: str,
    content_summary: str = None,
) -> Report:
    """Saves report reference record in the database."""
    report = Report(
        investigation_id=investigation_id,
        report_type=report_type,
        report_path=f"/exports/report_{investigation_id[:8]}.{report_type}",
        content_summary=content_summary or f"{report_type.upper()} Export for Investigation {investigation_id[:8]}",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


# ----------------------------------------------------------------------
# SYNTHESIS HELPERS
# ----------------------------------------------------------------------
def _synthesize_attack_surface(findings: List[Dict[str, Any]], risk_data: Dict[str, Any]) -> str:
    """Synthesizes high-level attack surface posture from deduplicated findings."""
    exposures = []
    for f in findings:
        m = f.get("module")
        if m == "ip" and f.get("severity") in ["HIGH", "CRITICAL"]:
            exposures.append(f"Exposed listening services on perimeter IP ({f.get('indicator')})")
        elif m == "email" and f.get("severity") in ["HIGH", "MEDIUM"]:
            exposures.append(f"Compromised credential records and/or missing SPF/DMARC spoofing controls ({f.get('indicator')})")
        elif m == "domain" and f.get("severity") in ["HIGH", "MEDIUM"]:
            exposures.append(f"Subdomain sprawl or SSL certificate misconfiguration ({f.get('indicator')})")
        elif m == "threat_intel" and f.get("severity") in ["CRITICAL", "HIGH"]:
            exposures.append(f"Active threat intelligence blacklisting on indicator ({f.get('indicator')})")

    if not exposures:
        return "Perimeter attack surface is relatively contained. No high-risk administrative services or active threat flags were discovered during the audit."
    return "Identified attack surface vectors include: " + "; ".join(exposures) + "."


def _synthesize_recommendations(findings: List[Dict[str, Any]], risk_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Builds prioritized remediation list from finding data."""
    recs = []
    seen = set()

    for f in findings:
        sev = f.get("severity", "LOW")
        rem = f.get("remediation")
        ind = f.get("indicator")
        if rem and rem not in seen:
            seen.add(rem)
            prio = "CRITICAL" if sev == "CRITICAL" else ("HIGH" if sev == "HIGH" else ("MEDIUM" if sev == "MEDIUM" else "LOW"))
            recs.append({
                "priority": prio,
                "title": f"Mitigate {f.get('module', '').upper()} Risk on {ind}",
                "action": rem,
                "target": ind,
                "rationale": f['description'],
            })

    if not recs:
        recs.append({
            "priority": "LOW",
            "title": "Maintain Baseline Threat & OSINT Monitoring",
            "action": "Ensure periodic domain registration audits and automated credential exposure tracking remain active.",
            "target": "Infrastructure Baseline",
            "rationale": "No critical or high-risk findings detected in current scan.",
        })

    # Sort: CRITICAL, HIGH, MEDIUM, LOW
    p_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recs.sort(key=lambda r: p_rank.get(r["priority"], 4))
    return recs[:8]


def _synthesize_limitations(raw_findings: List[Any]) -> List[str]:
    """Compiles clear technical constraints and scan boundaries for transparency."""
    from core.config import settings
    limits = [
        "Intelligence is based on passive collection and non-destructive active probes executed at the time of report generation.",
        "DNS records, WHOIS registrant details, and GeoIP routing tables reflect external authoritative states which may update over time.",
    ]
    if not settings.VIRUSTOTAL_API_KEY:
        limits.append("VirusTotal integration operated in offline seed simulation mode (VIRUSTOTAL_API_KEY not configured in backend).")
    if not settings.ABUSEIPDB_API_KEY:
        limits.append("AbuseIPDB integration operated in offline seed simulation mode (ABUSEIPDB_API_KEY not configured in backend).")
    if not settings.HIBP_API_KEY:
        limits.append("HaveIBeenPwned email breach lookup operated in simulation mode (HIBP_API_KEY not configured in backend).")

    limits.append("Absence of threat flags in public feeds does not guarantee the complete absence of advanced persistent threats (APTs) or zero-day vulnerabilities.")
    return limits
