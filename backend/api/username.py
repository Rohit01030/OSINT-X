"""
Username Intelligence API Router.
Provides endpoints for checking username profiles across web platforms.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from models.investigation import Investigation
from services import username_service
from api.deps import get_current_user
from core.rate_limit import limiter

router = APIRouter(prefix="/username", tags=["username"])


class UsernameAnalyzeRequest(BaseModel):
    investigation_id: str = Field(..., description="ID of the investigation case to attach findings to")
    target: str = Field(..., description="Username target to footprint, e.g. johndoe")


@router.post("/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("15/minute")
async def analyze_username(
    request: Request,
    payload: UsernameAnalyzeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes an asynchronous footprint lookup for the target username across popular developer and social sites,
    saving the profile matches in the findings database.
    """
    # Verify investigation case exists and check permission
    inv = db.query(Investigation).filter(Investigation.id == payload.investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation case not found",
        )

    if current_user.role != "admin" and inv.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this investigation case",
        )

    try:
        results = await username_service.analyze_username(db, payload.investigation_id, payload.target)
        return results
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Username analysis failed: {str(e)}")
