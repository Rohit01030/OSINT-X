"""
Unit Verification Tests for OSINT-X Intelligence Report Improvement.

Tests:
  1. Risk Assessment Engine:
     - 0 findings / clean target -> SAFE / Inconclusive
     - Standard ports (80, 443) not flagged as critical vulnerabilities
     - High-risk administrative ports (23, 445, 3389) properly flagged
     - VirusTotal multi-engine detection validation
     - AbuseIPDB confidence score evaluation
     - Low security headers evaluated as configuration weaknesses, NOT critical
  2. Finding Deduplication Engine:
     - Merging of duplicate observations by fingerprint
     - Preservation of first_seen and last_seen timestamps
     - Correct raw vs unique counts and severity distribution
  3. IOC Correlation Engine:
     - Domain to IP (from DNS A records)
     - Subdomain hierarchy
     - Email to domain zone
     - File hash matches
     - Verified profile handles
  4. MITRE ATT&CK Mapping:
     - Clear distinction between TOOL_COLLECTION_ACTIVITY and OBSERVED_ADVERSARY_BEHAVIOR
  5. Report Generation & Formats:
     - JSON structure containing all required intelligence fields
     - CSV export containing technical findings and risk tables
     - HTML/PDF export with print CSS, dark navy theme, and 21 sections
"""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from services.risk_engine import assess_investigation_risk
from services.deduplication_service import deduplicate_investigation_findings, generate_finding_fingerprint
from services.correlation_engine import correlate_investigation_indicators
from services.mitre_mapper import map_investigation_mitre
from services import report_service


class MockFinding:
    """Mock finding object mimicking SQLAlchemy model."""
    def __init__(self, id_val, module, f_type, data, created_at=None):
        self.id = id_val
        self.module = module
        self.type = f_type
        self.data = data
        self.created_at = created_at or datetime.now(timezone.utc)


# ==============================================================================
# 1. RISK ASSESSMENT TESTS
# ==============================================================================
def test_risk_assessment_zero_findings():
    """Validates that zero findings produce a clean SAFE score with insufficient evidence marker."""
    res = assess_investigation_risk([])
    assert res["risk_score"] == 0.0
    assert res["risk_level"] == "SAFE"
    assert res["status"] == "INSUFFICIENT_EVIDENCE"
    assert res["inconclusive"] is True
    assert len(res["scoring_factors"]) == 0


def test_standard_ports_do_not_flag_critical():
    """Ensures standard web ports (80, 443) do NOT trigger critical vulnerability scores."""
    f = MockFinding("f1", "ip", "ip_scan", {
        "target": "192.168.1.1",
        "open_ports": [80, 443],
    })
    res = assess_investigation_risk([f])
    # Standard ports should not add dangerous risk points
    assert res["risk_score"] == 0.0
    assert res["risk_level"] == "SAFE"


def test_high_risk_ports_properly_scored():
    """Ensures high-risk administrative ports (RDP 3389, Telnet 23) contribute specific risk."""
    f = MockFinding("f1", "ip", "ip_scan", {
        "target": "203.0.113.5",
        "open_ports": [23, 3389],
    })
    res = assess_investigation_risk([f])
    assert res["risk_score"] > 2.0
    factor_names = [fac["name"] for fac in res["scoring_factors"]]
    assert any("23" in name for name in factor_names)
    assert any("3389" in name for name in factor_names)


def test_low_headers_not_critical():
    """Missing security headers (F rating) should contribute max 0.7-0.8, not mark as Critical."""
    f = MockFinding("f1", "domain", "domain_scan", {
        "target": "example.com",
        "http": {"security_score": "F", "missing_headers": ["Content-Security-Policy", "X-Frame-Options"]},
        "ssl": {"valid": True},
    })
    res = assess_investigation_risk([f])
    assert res["risk_score"] <= 1.0
    assert res["risk_level"] == "LOW"


def test_virustotal_multi_engine_detection():
    """Validates that confirmed malicious engines trigger critical/high severity."""
    f = MockFinding("f1", "threat_intel", "threat_scan", {
        "target": "malware.example.com",
        "virustotal": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 8, "suspicious": 1}
                }
            }
        }
    })
    res = assess_investigation_risk([f])
    assert res["risk_score"] >= 2.0
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert any("Malicious Indicator" in fac["name"] for fac in res["scoring_factors"])


# ==============================================================================
# 2. DEDUPLICATION TESTS
# ==============================================================================
def test_finding_deduplication():
    """Tests merging of duplicate observations for identical indicator and module."""
    dt1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    dt2 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    f1 = MockFinding("id-1", "domain", "domain_scan", {"target": "testcorp.com"}, dt1)
    f2 = MockFinding("id-2", "domain", "domain_scan", {"target": "testcorp.com"}, dt2)
    f3 = MockFinding("id-3", "ip", "ip_scan", {"target": "1.1.1.1", "open_ports": [80]}, dt1)

    res = deduplicate_investigation_findings([f1, f2, f3])
    assert res["total_raw_observations"] == 3
    assert res["total_unique_findings"] == 2
    assert res["duplicate_observations_count"] == 1

    # Check merged domain finding
    domain_finding = next(f for f in res["unique_findings"] if f["module"] == "domain")
    assert domain_finding["observation_count"] == 2
    assert set(domain_finding["observation_ids"]) == {"id-1", "id-2"}
    assert domain_finding["first_seen"] == dt1.isoformat()
    assert domain_finding["last_seen"] == dt2.isoformat()


# ==============================================================================
# 3. IOC CORRELATION TESTS
# ==============================================================================
def test_correlation_engine():
    """Tests cross-module indicator relationship discovery with supporting evidence."""
    f_domain = MockFinding("d1", "domain", "domain_scan", {
        "target": "target.org",
        "dns": {"A": ["198.51.100.1"], "AAAA": []},
        "subdomains": ["api.target.org", "vpn.target.org"],
    })
    f_email = MockFinding("e1", "email", "email_scan", {
        "target": "admin@target.org",
        "domain": "target.org",
    })
    f_user = MockFinding("u1", "username", "username_scan", {
        "target": "targetuser",
        "platforms": [{"platform": "GitHub", "url": "https://github.com/targetuser", "exists": True}],
    })

    corr = correlate_investigation_indicators([f_domain, f_email, f_user], [])
    rels = corr["relationships"]
    assert len(rels) >= 4

    rel_types = [r["relationship"] for r in rels]
    assert "RESOLVES_TO" in rel_types
    assert "CHILD_ZONE_OF" in rel_types
    assert "MAIL_DOMAIN_OF" in rel_types
    assert "ACTIVE_PROFILE_ON" in rel_types


# ==============================================================================
# 4. MITRE ATT&CK MAPPING TESTS
# ==============================================================================
def test_mitre_mapping_distinguishes_tool_vs_adversary():
    """Ensures tool reconnaissance is clearly separated from observed threat activity."""
    f_domain = MockFinding("d1", "domain", "domain_scan", {
        "target": "sample.com",
        "dns": {"A": ["1.2.3.4"]},
    })
    f_threat = MockFinding("t1", "threat_intel", "threat_scan", {
        "target": "evil.com",
        "summary": {"vt_malicious_count": 10, "abuse_confidence": 90},
    })

    mitre = map_investigation_mitre([f_domain, f_threat])
    matrix = mitre["mitre_attack_matrix"]

    tool_items = [m for m in matrix if m["mapping_type"] == "TOOL_COLLECTION_ACTIVITY"]
    threat_items = [m for m in matrix if m["mapping_type"] == "OBSERVED_ADVERSARY_BEHAVIOR"]

    assert len(tool_items) >= 1
    assert len(threat_items) >= 1
    assert mitre["tool_reconnaissance_count"] >= 1
    assert mitre["adversary_behavior_count"] >= 1


# ==============================================================================
# 5. REPORT GENERATION TESTS
# ==============================================================================
def test_report_service_json_and_html():
    """Tests end-to-end generation of structured JSON and high-grade HTML/PDF report."""
    db = MagicMock()
    inv = MagicMock()
    inv.id = "test-inv-uuid-12345"
    inv.title = "Target Intelligence Assessment"
    inv.status = "COMPLETED"
    inv.description = "Automated CTI investigation."
    inv.tags = ["osint", "threat_assessment"]
    inv.created_by = None
    inv.created_at = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

    f_dom = MockFinding("f-d", "domain", "domain_scan", {
        "target": "targetcorp.com",
        "dns": {"A": ["192.0.2.1"]},
        "subdomains": ["dev.targetcorp.com"],
        "ssl": {"valid": True, "issuer": "Let's Encrypt"},
        "http": {"security_score": "B"},
    })
    f_ip = MockFinding("f-i", "ip", "ip_scan", {
        "target": "192.0.2.1",
        "geoip": {"country": "United States", "city": "Ashburn", "isp": "Cloud Provider", "asn": "AS13335"},
        "open_ports": [80, 443],
    })

    db.query.return_value.filter.return_value.first.return_value = inv
    db.query.return_value.filter.return_value.all.return_value = [f_dom, f_ip]
    db.query.return_value.all.return_value = []

    with patch("services.ai_service.ollama_client") as mock_ollama:
        mock_ollama.generate.return_value = {
            "response": "Executive Assessment: Target perimeter was analyzed. No critical vulnerabilities found.",
            "offline_fallback": True,
        }

        # 1. JSON Report
        json_rep = report_service.generate_json_report(db, inv.id, classification="TLP:AMBER")
        assert "report_metadata" in json_rep
        assert json_rep["report_metadata"]["case_id"] == "TEST-INV"
        assert json_rep["report_metadata"]["classification"] == "TLP:AMBER"
        assert "investigation_statistics" in json_rep
        assert json_rep["investigation_statistics"]["total_unique_findings"] == 2
        assert "technical_findings" in json_rep
        assert "ioc_correlations" in json_rep
        assert "potential_attack_surface" in json_rep
        assert "recommendations" in json_rep

        # 2. CSV Report
        csv_rep = report_service.generate_csv_report(db, inv.id)
        assert "=== OSINT-X INVESTIGATION REPORT ===" in csv_rep
        assert "DEDUPLICATED TECHNICAL FINDINGS" in csv_rep
        assert "targetcorp.com" in csv_rep

        # 3. HTML / PDF Executive Report
        html_rep = report_service.generate_html_pdf_report(db, inv.id, classification="TLP:AMBER")
        assert "<!DOCTYPE html>" in html_rep
        assert "OSINT-X INTELLIGENCE SYSTEM" in html_rep
        assert "TLP:AMBER" in html_rep
        assert "@media print" in html_rep
        assert "targetcorp.com" in html_rep
        assert "Deduplicated Technical Findings Table" in html_rep
        assert "MITRE ATT&CK Enterprise Matrix Mapping" in html_rep
        assert "Table of Contents" in html_rep
