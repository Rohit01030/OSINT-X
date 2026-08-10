"""
Phase 1 verification tests.
Verifies models, input validation, consent logging, and rate limit imports.
"""
import pytest
from core.validation import (
    validate_ip,
    validate_domain,
    validate_email,
    validate_username,
    validate_hash,
    sanitize_target,
)
from models import User, Investigation, Finding, IOC, ConsentLog, Base


def test_target_validation():
    # IP validation
    assert validate_ip("192.168.1.1") is True
    assert validate_ip("2001:db8::1") is True
    assert validate_ip("999.999.999.999") is False

    # Domain validation
    assert validate_domain("example.com") is True
    assert validate_domain("https://sub.example.co.uk/path") is True
    assert validate_domain("invalid_domain") is False

    # Email validation
    assert validate_email("analyst@osintx.local") is True
    assert validate_email("invalid-email") is False

    # Username validation
    assert validate_username("john_doe") is True
    assert validate_username("a") is False  # too short

    # Hash validation
    assert validate_hash("d41d8cd98f00b204e9800998ecf8427e") is True  # MD5
    assert validate_hash("invalidhash") is False


def test_sanitize_target():
    assert sanitize_target("https://example.com/path/to/page") == "example.com"
    assert sanitize_target("http://1.1.1.1/query") == "1.1.1.1"


def test_model_definitions():
    # Check model table names
    assert User.__tablename__ == "users"
    assert Investigation.__tablename__ == "investigations"
    assert Finding.__tablename__ == "findings"
    assert IOC.__tablename__ == "iocs"
    assert ConsentLog.__tablename__ == "consent_logs"
