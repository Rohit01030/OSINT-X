"""
File Intelligence Service Layer.
Computes cryptographic hashes (MD5, SHA-1, SHA-256) and parses EXIF metadata for uploaded files (using Pillow).
Stores findings and registers IOCs.
"""
import uuid
import hashlib
import logging
from io import BytesIO
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from PIL import Image
from PIL.ExifTags import TAGS
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_hash

logger = logging.getLogger(__name__)


def calculate_hashes(file_bytes: bytes) -> Dict[str, str]:
    """
    Computes MD5, SHA-1, and SHA-256 hashes for the given file bytes.
    """
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
    }


def extract_exif_metadata(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Attempts to read basic dimensions, format, and EXIF tags from image files.
    """
    result: Dict[str, Any] = {
        "is_image": False,
        "format": None,
        "width": None,
        "height": None,
        "exif": {},
        "error": None,
    }

    try:
        # Wrap bytes in a stream and open with Pillow
        stream = BytesIO(file_bytes)
        with Image.open(stream) as img:
            result["is_image"] = True
            result["format"] = img.format
            result["width"] = img.width
            result["height"] = img.height

            # Parse EXIF tags
            exif_data = img.getexif()
            if exif_data:
                exif_dict = {}
                for tag, value in exif_data.items():
                    tag_name = TAGS.get(tag, str(tag))
                    
                    # Convert non-standard values to JSON serializable structures
                    if isinstance(value, bytes):
                        try:
                            value = value.decode("utf-8", errors="ignore").strip()
                        except Exception:
                            value = str(value)
                    elif not isinstance(value, (str, int, float, bool, list, dict)) and value is not None:
                        value = str(value)

                    exif_dict[str(tag_name)] = value
                result["exif"] = exif_dict
    except Exception as e:
        logger.debug("Pillow failed to open image %s: %s", filename, e)
        # It's fine if it's not a parsable image (e.g. text/pdf file), just record the error/flag
        result["error"] = f"Not a parsable image or error: {str(e)}"

    return result


def analyze_file(db: Session, investigation_id: str, filename: str, file_bytes: bytes) -> Dict[str, Any]:
    """
    Main File Intelligence Scanner.
    Processes uploaded file, extracts hashes/EXIF metadata, and saves findings/IOCs.
    """
    logger.info("Starting file intelligence scan for filename: %s", filename)

    hashes = calculate_hashes(file_bytes)
    metadata = extract_exif_metadata(file_bytes, filename)

    finding_id = str(uuid.uuid4())

    scan_result = {
        "finding_id": finding_id,
        "target": filename,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "file_size_bytes": len(file_bytes),
        "hashes": hashes,
        "image_metadata": metadata,
        "summary": {
            "file_size": len(file_bytes),
            "sha256": hashes["sha256"],
            "is_image": metadata["is_image"],
            "image_format": metadata["format"],
        },
    }

    # Store finding in database
    finding = Finding(
        id=finding_id,
        investigation_id=investigation_id,
        module="file",
        type="file_scan",
        data=scan_result,
    )
    db.add(finding)

    # Store SHA-256 hash as an IOC
    sha256_hash = hashes["sha256"]
    ioc_hash = db.query(IOC).filter(IOC.value == sha256_hash).first()
    if not ioc_hash:
        db.add(IOC(value=sha256_hash, type="hash", source="file_module", reputation_score=0.0))

    db.commit()
    db.refresh(finding)

    return scan_result
