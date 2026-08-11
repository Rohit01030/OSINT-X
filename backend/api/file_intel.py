"""
File Intelligence API Router.
Provides endpoints for file analysis, calculating hashes, and extracting EXIF metadata from uploads.
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, File, Form, UploadFile, Request
from sqlalchemy.orm import Session

from database.session import get_db
from models.user import User
from models.investigation import Investigation
from services import file_service
from api.deps import get_current_user
from core.rate_limit import limiter

router = APIRouter(prefix="/file", tags=["file"])


@router.post("/analyze", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
@limiter.limit("15/minute")
async def analyze_file(
    request: Request,
    investigation_id: str = Form(..., description="ID of the investigation case to attach findings to"),
    file: UploadFile = File(..., description="File to upload and analyze"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Uploads a file, computes cryptographic hashes (MD5, SHA-1, SHA-256), extracts image EXIF metadata
    (dimensions, format, dates, GPS), and registers findings/IOCs under the investigation.
    """
    # Verify investigation case exists and check permission
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
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
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty file uploaded",
            )
        
        filename = file.filename or "unnamed_file"
        results = file_service.analyze_file(db, investigation_id, filename, file_bytes)
        return results
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"File analysis failed: {str(e)}")
