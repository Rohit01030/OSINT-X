# backend/services/phone_service.py
"""
Phone Number OSINT service.

Provides:
- Validation & parsing via `phonenumbers`.
- Carrier, region, timezone, and number type.
- Optional reputation lookup via NumVerify (free tier).
"""

import phonenumbers
from phonenumbers import carrier, geocoder, timezone, NumberParseException
import requests
from typing import Dict, Any, Optional
import os

NUMVERIFY_ENDPOINT = "http://apilayer.net/api/validate"


def _load_numverify_key() -> Optional[str]:
    return os.getenv("NUMVERIFY_API_KEY")


def parse_phone(number: str) -> Dict[str, Any]:
    """Parse and validate a phone number.

    Returns a dict with keys:
        valid (bool), e164 (str|None), country (str|None), carrier (str|None),
        region (str|None), timezone (list[str]|None), number_type (str|None)
    """
    try:
        parsed = phonenumbers.parse(number, None)
        valid = phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed)
    except NumberParseException:
        return {"valid": False}

    if not valid:
        return {"valid": False}

    return {
        "valid": True,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "country": geocoder.country_name_for_number(parsed, "en"),
        "carrier": carrier.name_for_number(parsed, "en"),
        "region": geocoder.description_for_number(parsed, "en"),
        "timezone": timezone.time_zones_for_number(parsed),
        "number_type": phonenumbers.number_type(parsed).name,
    }


def _query_numverify(e164: str) -> Optional[Dict[str, Any]]:
    """Optional reputation data from NumVerify.
    Returns dict with line_type, location, carrier, risk etc. if API key is present.
    """
    api_key = _load_numverify_key()
    if not api_key:
        return None
    try:
        resp = requests.get(
            NUMVERIFY_ENDPOINT,
            params={"access_key": api_key, "number": e164, "format": 1},
            timeout=8,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not data.get("valid"):
            return None
        return {
            "line_type": data.get("line_type"),
            "carrier": data.get("carrier"),
            "location": data.get("location"),
            "country_prefix": data.get("country_prefix"),
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "risk": data.get("risk"),
        }
    except Exception:
        return None


def analyze_phone(number: str) -> Dict[str, Any]:
    """Full phone analysis – combines local parsing with optional NumVerify data."""
    parsed = parse_phone(number)
    if parsed.get("valid") and parsed.get("e164"):
        enrich = _query_numverify(parsed["e164"])
        if enrich:
            parsed.update(enrich)
    return parsed
