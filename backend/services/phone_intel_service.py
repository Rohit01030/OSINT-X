'''Phone Intelligence Service.
Provides lookup and validation for phone numbers.
If NUMVERIFY_API_KEY is not set, operates in deterministic simulation mode.
''' 
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx

from core.config import settings

logger = logging.getLogger(__name__)

def _simulate_phone_lookup(phone_number: str) -> Dict[str, Any]:
    """Return deterministic mock data for a phone number.
    The simulation treats numbers ending with "0000" as invalid.
    """
    is_invalid = phone_number.strip().endswith("0000")
    return {
        "valid": not is_invalid,
        "number": phone_number,
        "local_format": phone_number if not is_invalid else None,
        "international_format": f"+{phone_number}" if not is_invalid else None,
        "country_prefix": "+1" if not is_invalid else None,
        "country_code": "US" if not is_invalid else None,
        "country_name": "United States" if not is_invalid else None,
        "location": "California" if not is_invalid else None,
        "carrier": "Verizon" if not is_invalid else None,
        "line_type": "mobile" if not is_invalid else None,
        "error": None if not is_invalid else "Invalid number",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

def lookup_phone(phone_number: str) -> Dict[str, Any]:
    """Lookup a phone number via NumVerify (or simulation).
    Returns a dictionary with keys matching the free API response.
    """
    if not settings.NUMVERIFY_API_KEY:
        logger.info("NumVerify API key missing – using simulation for phone lookup")
        return _simulate_phone_lookup(phone_number)

    url = "http://apilayer.net/api/validate"
    params = {
        "access_key": settings.NUMVERIFY_API_KEY,
        "number": phone_number,
        "format": 1,
    }
    try:
        with httpx.Client(timeout=8.0) as client:
            resp = client.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning("NumVerify API returned status %s", resp.status_code)
                return {"error": f"NumVerify API error status: {resp.status_code}"}
    except Exception as e:
        logger.error("Error querying NumVerify API: %s", e)
        # Fallback to deterministic simulation for testing stability
        return _simulate_phone_lookup(phone_number)
