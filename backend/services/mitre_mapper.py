"""
OSINT-X MITRE ATT&CK Matrix Mapping Service.

Maps investigation findings to the MITRE ATT&CK for Enterprise framework.
Crucially distinguishes between:
  1. TOOL_COLLECTION_ACTIVITY: Passive OSINT collection executed by OSINT-X to gather data
     (e.g., OSINT-X queried passive DNS; this does NOT mean the target was compromised).
  2. OBSERVED_ADVERSARY_BEHAVIOR: Concrete threat intelligence or telemetry indicating actual
     host compromise or adversary-aligned operations (e.g., active malicious malware C2 communications).
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Base reconnaissance mappings for OSINT-X collection actions
TECHNIQUE_CATALOG = {
    "domain_dns": {
        "technique_id": "T1590.002",
        "tactic": "Reconnaissance",
        "technique_name": "Gather Victim Network Information: DNS",
        "description": "Adversaries may gather DNS data to map network architecture and locate key infrastructure.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "OSINT-X queried authoritative DNS servers (A, AAAA, MX, NS, TXT) to discover domain architecture.",
        "confidence": "HIGH",
    },
    "domain_subdomains": {
        "technique_id": "T1596.001",
        "tactic": "Reconnaissance",
        "technique_name": "Search Open Websites/Domains: DNS/Certificate Transparency",
        "description": "Adversaries search Certificate Transparency logs and DNS tables to enumerate subdomains.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "OSINT-X performed passive certificate transparency and wordlist probing to map subdomains.",
        "confidence": "HIGH",
    },
    "ip_ports": {
        "technique_id": "T1595.002",
        "tactic": "Reconnaissance",
        "technique_name": "Active Scanning: Vulnerability Scanning / Port Probing",
        "description": "Adversaries scan public IP ranges to identify open TCP/UDP network ports and services.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "Active socket connection checks were executed across target IP ports with operator consent.",
        "confidence": "HIGH",
    },
    "ip_whois": {
        "technique_id": "T1590.005",
        "tactic": "Reconnaissance",
        "technique_name": "Gather Victim Network Information: IP Addresses",
        "description": "Adversaries collect IP allocations and autonomous system numbers (ASNs) from registry databases.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "OSINT-X queried GeoIP and BGP routing databases to identify ISP and geographical hosting.",
        "confidence": "HIGH",
    },
    "email_breaches": {
        "technique_id": "T1589.001",
        "tactic": "Reconnaissance",
        "technique_name": "Gather Victim Identity Information: Credentials",
        "description": "Adversaries search public breach repositories to acquire exposed credentials for password stuffing.",
        "mapping_type": "OBSERVED_ADVERSARY_BEHAVIOR",
        "mapping_reason": "Target email was confirmed present in historic credential breach data dumps.",
        "confidence": "HIGH",
    },
    "email_spf_dmarc": {
        "technique_id": "T1589.002",
        "tactic": "Reconnaissance",
        "technique_name": "Gather Victim Identity Information: Email Addresses",
        "description": "Adversaries map organizational email domains and inspect spoofing defenses to plan phishing campaigns.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "Audited authoritative SPF, DKIM, and DMARC TXT records to assess domain spoofability.",
        "confidence": "HIGH",
    },
    "username_enumeration": {
        "technique_id": "T1589.003",
        "tactic": "Reconnaissance",
        "technique_name": "Gather Victim Identity Information: Employee Names / Usernames",
        "description": "Adversaries enumerate social media and developer profiles to correlate target identities.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "Automated probes queried 15 public platforms to identify matching user profile handles.",
        "confidence": "HIGH",
    },
    "threat_malicious": {
        "technique_id": "T1566",
        "tactic": "Initial Access",
        "technique_name": "Phishing / Malicious Infrastructure",
        "description": "Adversaries utilize known malicious infrastructure or malware droppers to gain initial network access.",
        "mapping_type": "OBSERVED_ADVERSARY_BEHAVIOR",
        "mapping_reason": "Threat intelligence databases confirmed target indicator is associated with active malware or phishing campaigns.",
        "confidence": "CONFIRMED",
    },
    "file_analysis": {
        "technique_id": "T1592",
        "tactic": "Reconnaissance",
        "technique_name": "Gather Victim Host Information: Hardware / Software Metadata",
        "description": "Adversaries inspect file artifacts and EXIF camera/device metadata to learn victim internal details.",
        "mapping_type": "TOOL_COLLECTION_ACTIVITY",
        "mapping_reason": "OSINT-X extracted image metadata (Make, Model, Software, Timestamps) and cryptographic hashes.",
        "confidence": "HIGH",
    },
}


def map_investigation_mitre(findings: List[Any]) -> Dict[str, Any]:
    """
    Evaluates investigation findings to build an evidence-backed MITRE ATT&CK Matrix mapping.
    Ensures clear separation between OSINT collection methods and observed threat activity.
    """
    mapped_items: List[Dict[str, Any]] = []
    seen_ids = set()

    has_threat_intel_malicious = False

    for f in findings:
        module = getattr(f, "module", "")
        data = getattr(f, "data", {})
        if not isinstance(data, dict):
            continue

        target = data.get("target") or "target"

        if module == "domain":
            if "domain_dns" not in seen_ids:
                seen_ids.add("domain_dns")
                item = dict(TECHNIQUE_CATALOG["domain_dns"])
                item["evidence"] = f"DNS queries executed for domain '{target}'"
                mapped_items.append(item)

            if data.get("subdomains"):
                if "domain_subdomains" not in seen_ids:
                    seen_ids.add("domain_subdomains")
                    item = dict(TECHNIQUE_CATALOG["domain_subdomains"])
                    item["evidence"] = f"{len(data['subdomains'])} subdomains mapped under '{target}'"
                    mapped_items.append(item)

        elif module == "ip":
            if "ip_whois" not in seen_ids:
                seen_ids.add("ip_whois")
                item = dict(TECHNIQUE_CATALOG["ip_whois"])
                item["evidence"] = f"BGP and GeoIP lookup performed on IP '{target}'"
                mapped_items.append(item)

            if data.get("open_ports"):
                if "ip_ports" not in seen_ids:
                    seen_ids.add("ip_ports")
                    item = dict(TECHNIQUE_CATALOG["ip_ports"])
                    port_list = [p.get('port', p) if isinstance(p, dict) else p for p in data['open_ports']] if isinstance(data['open_ports'], list) else []
                    item["evidence"] = f"Socket port probing identified listening ports {port_list[:6]} on '{target}'"
                    mapped_items.append(item)

        elif module == "email":
            if "email_spf_dmarc" not in seen_ids:
                seen_ids.add("email_spf_dmarc")
                item = dict(TECHNIQUE_CATALOG["email_spf_dmarc"])
                item["evidence"] = f"SPF/DMARC mail authentication verification performed for '{target}'"
                mapped_items.append(item)

            raw_breaches = data.get("breaches", {})
            b_count = raw_breaches.get("total_breaches", 0) if isinstance(raw_breaches, dict) else (len(raw_breaches) if isinstance(raw_breaches, list) else 0)
            if b_count > 0 and "email_breaches" not in seen_ids:
                seen_ids.add("email_breaches")
                item = dict(TECHNIQUE_CATALOG["email_breaches"])
                item["evidence"] = f"Email '{target}' verified in {b_count} public breach dump(s)"
                mapped_items.append(item)

        elif module == "username":
            if "username_enumeration" not in seen_ids:
                seen_ids.add("username_enumeration")
                item = dict(TECHNIQUE_CATALOG["username_enumeration"])
                found = (data.get("summary") or {}).get("total_found", 0)
                item["evidence"] = f"Probed username '{target}' across public social media platforms ({found} active profiles)"
                mapped_items.append(item)

        elif module == "file":
            if "file_analysis" not in seen_ids:
                seen_ids.add("file_analysis")
                item = dict(TECHNIQUE_CATALOG["file_analysis"])
                item["evidence"] = f"Extracted EXIF metadata and calculated SHA-256 for '{target}'"
                mapped_items.append(item)

        elif module == "threat_intel":
            summary = data.get("summary") or {}
            vt_mal = summary.get("vt_malicious_count", 0)
            abuse_conf = summary.get("abuse_confidence", 0)

            if (vt_mal >= 3 or abuse_conf >= 50) and "threat_malicious" not in seen_ids:
                seen_ids.add("threat_malicious")
                item = dict(TECHNIQUE_CATALOG["threat_malicious"])
                item["evidence"] = f"Indicator '{target}' flagged by {vt_mal} VT engines and AbuseIPDB ({abuse_conf}%)"
                mapped_items.append(item)
                has_threat_intel_malicious = True

    # If no findings recorded, provide a single generic informational entry
    if not mapped_items:
        item = dict(TECHNIQUE_CATALOG["domain_dns"])
        item["evidence"] = "Baseline reconnaissance capability ready; no active findings recorded."
        item["confidence"] = "LOW"
        mapped_items.append(item)

    tool_recon_count = sum(1 for m in mapped_items if m.get("mapping_type") == "TOOL_COLLECTION_ACTIVITY")
    adversary_behavior_count = sum(1 for m in mapped_items if m.get("mapping_type") == "OBSERVED_ADVERSARY_BEHAVIOR")

    return {
        "total_techniques_mapped": len(mapped_items),
        "tool_reconnaissance_count": tool_recon_count,
        "adversary_behavior_count": adversary_behavior_count,
        "mitre_attack_matrix": mapped_items,
    }
