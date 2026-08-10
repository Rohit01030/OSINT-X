"""
Rate limiting configuration powered by slowapi.
Protects OSINT modules and external API quotas from rate abuse.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["60 per minute"])
