"""
Report Generator Service for OSINT-X.

Compiles investigation data into structured JSON, tabular CSV, and print-ready
HTML/PDF Executive Intelligence Briefings.
"""
import json
import csv
import io
import logging
from typing import Dict, Any
from sqlalchemy.orm import Session

from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from models.consent_log import ConsentLog
from models.report import Report
from services import ai_service, visualization_service

logger = logging.getLogger(__name__)


def generate_json_report(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Compiles complete structured JSON report for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    iocs = db.query(IOC).all()
    consent_logs = db.query(ConsentLog).filter(ConsentLog.investigation_id == investigation_id).all()

    # AI engine intelligence
    summary = ai_service.generate_investigation_summary(db, investigation_id)
    risk_info = ai_service.calculate_and_explain_risk(db, investigation_id)
    mitre_info = ai_service.map_mitre_attack(db, investigation_id)
    metrics = visualization_service.get_chart_metrics(db, investigation_id)

    report_payload = {
        "report_metadata": {
            "platform": "OSINT-X Intelligence Platform",
            "version": "1.0.0",
            "investigation_id": inv.id,
            "title": inv.title,
            "status": inv.status,
            "description": inv.description,
            "tags": inv.tags or [],
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
        },
        "executive_summary": summary.get("summary", ""),
        "risk_assessment": {
            "risk_score": risk_info.get("risk_score", 0.0),
            "risk_level": risk_info.get("risk_level", "LOW"),
            "risk_factors": risk_info.get("risk_factors", []),
            "explanation": risk_info.get("explanation", "")
        },
        "mitre_attack_matrix": mitre_info.get("mitre_attack_matrix", []),
        "metrics_summary": metrics.get("module_distribution", {}),
        "findings": [
            {
                "id": f.id,
                "module": f.module,
                "type": f.type,
                "data": f.data,
                "created_at": f.created_at.isoformat() if f.created_at else None
            }
            for f in findings
        ],
        "iocs": [
            {
                "id": i.id,
                "value": i.value,
                "type": i.type,
                "source": i.source,
                "reputation_score": i.reputation_score
            }
            for i in iocs
        ],
        "consent_audit_trail": [
            {
                "id": c.id,
                "target": c.target,
                "confirmed_at": c.confirmed_at.isoformat() if c.confirmed_at else None,
                "ip_address": c.ip_address
            }
            for c in consent_logs
        ]
    }

    return report_payload


def generate_csv_report(db: Session, investigation_id: str) -> str:
    """Formats findings and IOC records into CSV tabular string data."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return "Error: Investigation not found"

    output = io.StringIO()
    writer = csv.writer(output)

    # Section 1: Case Info Header
    writer.writerow(["=== OSINT-X INVESTIGATION REPORT ==="])
    writer.writerow(["Investigation ID", inv.id])
    writer.writerow(["Title", inv.title])
    writer.writerow(["Status", inv.status])
    writer.writerow(["Description", inv.description or "N/A"])
    writer.writerow([])

    # Section 2: Findings Table
    writer.writerow(["=== FINDINGS TABLE ==="])
    writer.writerow(["Finding ID", "Module", "Type", "Created At", "Target / Summary"])
    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    
    for f in findings:
        target = (f.data or {}).get("target", "N/A")
        created = f.created_at.isoformat() if f.created_at else ""
        writer.writerow([f.id, f.module.upper(), f.type, created, target])

    writer.writerow([])

    # Section 3: IOC Table
    writer.writerow(["=== IOC INDICATORS TABLE ==="])
    writer.writerow(["IOC ID", "Type", "Indicator Value", "Source", "Reputation Score"])
    iocs = db.query(IOC).all()
    for i in iocs:
        writer.writerow([i.id, i.type.upper(), i.value, i.source, i.reputation_score])

    return output.getvalue()


def generate_html_pdf_report(db: Session, investigation_id: str) -> str:
    """Renders a styled HTML Executive Intelligence Briefing."""
    json_rep = generate_json_report(db, investigation_id)
    if "error" in json_rep:
        return "<html><body><h1>Error: Investigation not found</h1></body></html>"

    meta = json_rep["report_metadata"]
    risk = json_rep["risk_assessment"]
    findings = json_rep["findings"]
    mitre = json_rep["mitre_attack_matrix"]

    findings_rows = "".join(
        f"<tr>"
        f"<td style='padding:8px;border:1px solid #374151;'>{f['module'].upper()}</td>"
        f"<td style='padding:8px;border:1px solid #374151;'>{f['type']}</td>"
        f"<td style='padding:8px;border:1px solid #374151;'>{f.get('data', {}).get('target', 'N/A')}</td>"
        f"<td style='padding:8px;border:1px solid #374151;'>{f['created_at']}</td>"
        f"</tr>"
        for f in findings
    ) or "<tr><td colspan='4' style='padding:8px;'>No findings recorded.</td></tr>"

    mitre_rows = "".join(
        f"<tr>"
        f"<td style='padding:8px;border:1px solid #374151;color:#10B981;font-weight:bold;'>{m['technique_id']}</td>"
        f"<td style='padding:8px;border:1px solid #374151;'>{m['tactic']}</td>"
        f"<td style='padding:8px;border:1px solid #374151;'>{m['technique_name']}</td>"
        f"</tr>"
        for m in mitre
    ) or "<tr><td colspan='3' style='padding:8px;'>No MITRE techniques mapped.</td></tr>"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>OSINT-X Intelligence Briefing - {meta['title']}</title>
    <style>
        body {{
            font-family: monospace, sans-serif;
            background-color: #111827;
            color: #F9FAFB;
            margin: 0;
            padding: 30px;
            line-height: 1.6;
        }}
        .header {{
            border-bottom: 2px solid #10B981;
            padding-bottom: 15px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .title {{
            font-size: 22px;
            font-weight: bold;
            color: #10B981;
        }}
        .badge {{
            background-color: #1F2937;
            border: 1px solid #374151;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
        }}
        .section {{
            background-color: #1F2937;
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .section-title {{
            font-size: 14px;
            font-weight: bold;
            color: #10B981;
            margin-bottom: 10px;
            border-bottom: 1px solid #374151;
            padding-bottom: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 10px;
        }}
        th {{
            background-color: #111827;
            color: #10B981;
            padding: 8px;
            border: 1px solid #374151;
            text-align: left;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">OSINT-X Intelligence Briefing</div>
            <div style="font-size:12px;color:#9CA3AF;">Case: {meta['title']} (ID: {meta['investigation_id']})</div>
        </div>
        <div class="badge">Status: {meta['status'].upper()}</div>
    </div>

    <div class="section">
        <div class="section-title">1. Executive Summary (Local AI Narrative)</div>
        <p style="white-space: pre-wrap; font-size: 12px; color: #E5E7EB;">{json_rep['executive_summary']}</p>
    </div>

    <div class="section">
        <div class="section-title">2. Risk Assessment Rating</div>
        <div style="font-size: 16px; font-weight: bold;">
            Risk Score: <span style="color:#10B981;">{risk['risk_score']} / 10.0</span> ({risk['risk_level']})
        </div>
        <p style="font-size: 12px; color: #D1D5DB; margin-top: 8px;">{risk['explanation']}</p>
    </div>

    <div class="section">
        <div class="section-title">3. Technical Findings Breakdown ({len(findings)} Total)</div>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Scan Type</th>
                    <th>Target</th>
                    <th>Discovered At</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>
    </div>

    <div class="section">
        <div class="section-title">4. MITRE ATT&CK Matrix Recon Mapping</div>
        <table>
            <thead>
                <tr>
                    <th>Technique ID</th>
                    <th>Tactic</th>
                    <th>Technique Name</th>
                </tr>
            </thead>
            <tbody>
                {mitre_rows}
            </tbody>
        </table>
    </div>

    <div style="text-align: center; font-size: 10px; color: #6B7280; margin-top: 30px;">
        Generated automatically by OSINT-X Intelligence Platform • Authorized Use Only
    </div>
</body>
</html>"""
    return html_content


def save_report_record(db: Session, investigation_id: str, report_type: str, content_summary: str = None) -> Report:
    """Saves report reference record in the database."""
    report = Report(
        investigation_id=investigation_id,
        report_type=report_type,
        report_path=f"/exports/report_{investigation_id[:8]}.{report_type}",
        content_summary=content_summary or f"{report_type.upper()} Export for Investigation {investigation_id[:8]}"
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
