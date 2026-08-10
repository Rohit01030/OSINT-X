"""
Input validation and target sanitization utilities.
Ensures targets passed to OSINT modules are valid and safe before execution.
"""
import ipaddress
import re

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,50}$")
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def validate_ip(target: str) -> bool:
    """Validates if target string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def validate_domain(target: str) -> bool:
    """Validates if target string is a valid domain format."""
    clean_target = target.strip().lower()
    if clean_target.startswith("http://") or clean_target.startswith("https://"):
        clean_target = clean_target.split("//")[1].split("/")[0]
    return bool(DOMAIN_REGEX.match(clean_target))


def validate_email(target: str) -> bool:
    """Validates email format."""
    return bool(EMAIL_REGEX.match(target.strip()))


def validate_username(target: str) -> bool:
    """Validates username string (alphanumeric, dots, underscores, dashes, length 3-50)."""
    return bool(USERNAME_REGEX.match(target.strip()))


def validate_hash(target: str) -> bool:
    """Validates if target is MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex)."""
    return bool(HASH_REGEX.match(target.strip()))


def sanitize_target(target: str) -> str:
    """Strips protocols, trailing slashes, and leading/trailing whitespace."""
    target = target.strip()
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    return target.split("/")[0]
