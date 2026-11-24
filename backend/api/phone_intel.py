'''Phone OSINT API router.
Provides HTTP endpoints for phone number lookup.
''' 
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from services.phone_intel_service import lookup_phone
from api.deps import get_current_user

router = APIRouter(tags=["phone"])

@router.get("/phone/lookup")
def phone_lookup(number: str, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()), user: dict = Depends(get_current_user)):
    """Lookup a phone number and return validation info.
    Returns the raw dict from the service (simulation or real).
    """
    if not number:
        raise HTTPException(status_code=400, detail="Phone number is required")
    result = lookup_phone(number)
    return result
