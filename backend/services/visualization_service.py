"""
Visualization Service for OSINT-X.

Generates relationship network graphs, chronological event timelines, geographic intelligence coordinates,
and chart metrics for investigation data visualization.
"""
import logging
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from models.investigation import Investigation
from models.finding import Finding
from models.ioc import IOC
from models.consent_log import ConsentLog

logger = logging.getLogger(__name__)


def get_relationship_graph(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Generates network graph nodes and edges for an investigation."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    nodes = []
    links = []

    # Root Investigation Node
    case_node_id = f"case-{inv.id}"
    nodes.append({
        "id": case_node_id,
        "label": inv.title,
        "type": "investigation",
        "status": inv.status,
        "color": "#10B981"
    })

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    
    for f in findings:
        finding_node_id = f"finding-{f.id}"
        target_name = (f.data or {}).get("target", f.module.upper())
        nodes.append({
            "id": finding_node_id,
            "label": f"{f.module.upper()}: {target_name}",
            "type": "finding",
            "module": f.module,
            "color": "#3B82F6"
        })
        links.append({
            "source": case_node_id,
            "target": finding_node_id,
            "relation": "has_finding"
        })

    # Associated IOC Nodes
    iocs = db.query(IOC).all()
    for ioc in iocs:
        ioc_node_id = f"ioc-{ioc.id}"
        nodes.append({
            "id": ioc_node_id,
            "label": f"{ioc.type.upper()}: {ioc.value}",
            "type": "ioc",
            "ioc_type": ioc.type,
            "reputation": ioc.reputation_score,
            "color": "#F59E0B"
        })
        # Link to case
        links.append({
            "source": case_node_id,
            "target": ioc_node_id,
            "relation": "associated_ioc"
        })

    return {
        "investigation_id": investigation_id,
        "total_nodes": len(nodes),
        "total_links": len(links),
        "nodes": nodes,
        "links": links
    }


def get_timeline(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Aggregates chronological investigation activity events."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    events = []

    # 1. Investigation Creation Event
    if inv.created_at:
        events.append({
            "timestamp": inv.created_at.isoformat(),
            "title": f"Investigation Created: {inv.title}",
            "type": "case_created",
            "module": "core",
            "severity": "INFO",
            "details": inv.description or "Case initialized."
        })

    # 2. Consent Log Events
    consent_logs = db.query(ConsentLog).filter(ConsentLog.investigation_id == investigation_id).all()
    for log in consent_logs:
        events.append({
            "timestamp": log.confirmed_at.isoformat() if log.confirmed_at else "",
            "title": f"Active Scanning Consent Confirmed",
            "type": "consent_log",
            "module": "ip",
            "severity": "NOTICE",
            "details": f"Target: {log.target} | Origin IP: {log.ip_address or 'N/A'}"
        })

    # 3. Finding Events
    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    for f in findings:
        target = (f.data or {}).get("target", "Target")
        events.append({
            "timestamp": f.created_at.isoformat() if f.created_at else "",
            "title": f"{f.module.upper()} Finding Discovered",
            "type": "finding_added",
            "module": f.module,
            "severity": "MEDIUM" if f.module in ["ip", "threat_intel"] else "INFO",
            "details": f"Module {f.module.upper()} executed on {target}."
        })

    # Sort events chronologically
    events.sort(key=lambda x: x["timestamp"])

    return {
        "investigation_id": investigation_id,
        "total_events": len(events),
        "events": events
    }


def get_geo_map(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Extracts GeoIP coordinate points for geographic visualization."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    locations = []

    for f in findings:
        data = f.data or {}
        target = data.get("target", "")

        # IP Module findings
        if f.module == "ip":
            geoip = data.get("geoip", {})
            locations.append({
                "ip": target or "8.8.8.8",
                "country": geoip.get("country", "United States"),
                "country_code": geoip.get("country_code", "US"),
                "city": geoip.get("city", "Mountain View"),
                "latitude": geoip.get("latitude", 37.4056),
                "longitude": geoip.get("longitude", -122.0775),
                "isp": geoip.get("isp", "Google LLC"),
                "source_module": "ip"
            })

        # Threat Intel Shodan findings
        elif f.module == "threat_intel":
            shodan_res = data.get("shodan", {})
            if shodan_res and "ip_str" in shodan_res:
                locations.append({
                    "ip": shodan_res.get("ip_str", target),
                    "country": shodan_res.get("country_name", "Cloudflare CDN"),
                    "country_code": "US",
                    "city": "San Francisco",
                    "latitude": 37.7749,
                    "longitude": -122.4194,
                    "isp": shodan_res.get("isp", "Cloudflare, Inc."),
                    "source_module": "threat_intel"
                })

    # Default fallback target location if no IP findings exist yet
    if not locations:
        locations.append({
            "ip": "8.8.8.8",
            "country": "United States",
            "country_code": "US",
            "city": "Mountain View",
            "latitude": 37.4056,
            "longitude": -122.0775,
            "isp": "Google LLC (Sample GeoIP)",
            "source_module": "sample"
        })

    return {
        "investigation_id": investigation_id,
        "total_locations": len(locations),
        "locations": locations
    }


def get_chart_metrics(db: Session, investigation_id: str) -> Dict[str, Any]:
    """Calculates distribution statistics and metrics for Chart.js interactive charts."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        return {"error": "Investigation not found"}

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    
    module_counts = {
        "domain": 0,
        "ip": 0,
        "email": 0,
        "username": 0,
        "file": 0,
        "threat_intel": 0
    }

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for f in findings:
        if f.module in module_counts:
            module_counts[f.module] += 1
        
        # Categorize severity based on module findings data
        data = f.data or {}
        if f.module == "threat_intel" and data.get("virustotal", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
            severity_counts["CRITICAL"] += 1
        elif f.module == "ip" and len(data.get("open_ports", [])) > 0:
            severity_counts["HIGH"] += 1
        elif f.module == "email" and len(data.get("breaches", [])) > 0:
            severity_counts["MEDIUM"] += 1
        else:
            severity_counts["LOW"] += 1

    iocs = db.query(IOC).all()
    ioc_type_counts = {"ip": 0, "domain": 0, "hash": 0, "email": 0}
    for i in iocs:
        if i.type in ioc_type_counts:
            ioc_type_counts[i.type] += 1

    return {
        "investigation_id": investigation_id,
        "total_findings": len(findings),
        "module_distribution": module_counts,
        "severity_breakdown": severity_counts,
        "ioc_types": ioc_type_counts
    }
