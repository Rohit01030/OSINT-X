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
    seen_ips = set()

    for f in findings:
        data = f.data or {}
        target = data.get("target", "")

        # IP Module findings
        if f.module == "ip":
            geoip = data.get("geoip", {})
            lat = geoip.get("lat") or geoip.get("latitude")
            lon = geoip.get("lon") or geoip.get("longitude")
            if target and target not in seen_ips and lat and lon:
                seen_ips.add(target)
                locations.append({
                    "ip": target,
                    "country": geoip.get("country", "Unknown"),
                    "country_code": geoip.get("country_code", "??"),
                    "city": geoip.get("city", "Unknown"),
                    "latitude": lat,
                    "longitude": lon,
                    "isp": geoip.get("isp", "Unknown"),
                    "asn": geoip.get("asn"),
                    "geo_source": geoip.get("geo_source", "ip-api.com"),
                    "reverse_dns_count": len(data.get("reverse_dns_domains", [])),
                    "open_ports_count": len(data.get("open_ports", [])),
                    "threat_level": (data.get("reputation") or {}).get("threat_level", "Clean"),
                    "source_module": "ip",
                })

        # Domain module findings — extract resolved IPs if present
        elif f.module == "domain":
            dns_records = data.get("dns_records", {})
            a_records = dns_records.get("A", [])
            for ip_addr in a_records:
                if ip_addr and ip_addr not in seen_ips:
                    seen_ips.add(ip_addr)
                    locations.append({
                        "ip": ip_addr,
                        "country": "Resolved from domain",
                        "country_code": "??",
                        "city": target,
                        "latitude": None,
                        "longitude": None,
                        "isp": "",
                        "source_module": "domain",
                    })

        # Threat Intel Shodan findings
        elif f.module == "threat_intel":
            shodan_res = data.get("shodan", {})
            if shodan_res and "ip_str" in shodan_res:
                s_ip = shodan_res.get("ip_str", target)
                if s_ip and s_ip not in seen_ips:
                    seen_ips.add(s_ip)
                    locations.append({
                        "ip": s_ip,
                        "country": shodan_res.get("country_name", "Unknown"),
                        "country_code": shodan_res.get("country_code", "??"),
                        "city": shodan_res.get("city", "Unknown"),
                        "latitude": shodan_res.get("latitude"),
                        "longitude": shodan_res.get("longitude"),
                        "isp": shodan_res.get("isp", "Unknown"),
                        "source_module": "threat_intel",
                    })

    # Filter out locations without valid coordinates for map rendering
    map_locations = [loc for loc in locations if loc.get("latitude") and loc.get("longitude")]

    return {
        "investigation_id": investigation_id,
        "total_locations": len(map_locations),
        "total_ip_findings": len(locations),
        "locations": map_locations,
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
