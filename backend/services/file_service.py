"""
File Intelligence Service Layer.
Computes cryptographic hashes (MD5, SHA-1, SHA-256), performs magic-byte MIME inspection,
extracts rich EXIF metadata (camera, GPS geolocation, timestamps) using Pillow,
inspects document and executable headers, queries threat intelligence reputation,
and registers findings/IOCs.
"""
import uuid
import hashlib
import logging
import mimetypes
import struct
import zipfile
import zlib
import re
import xml.etree.ElementTree as ET
from io import BytesIO
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS, IFD
from sqlalchemy.orm import Session

from models.finding import Finding
from models.ioc import IOC
from core.validation import validate_hash
from services.threat_intel_service import check_virustotal

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


def format_file_size(size_bytes: int) -> str:
    """
    Returns a human-readable file size string.
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def detect_mime_type(file_bytes: bytes, filename: str) -> str:
    """
    Inspects magic header bytes to reliably detect the real MIME type,
    falling back to file extension heuristics.
    """
    header = file_bytes[:32]

    # Image magic bytes
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
        return "image/gif"
    if header.startswith(b"RIFF") and b"WEBP" in header[8:16]:
        return "image/webp"
    if header.startswith(b"BM"):
        return "image/bmp"
    if header.startswith(b"\x00\x00\x01\x00") or header.startswith(b"\x00\x00\x02\x00"):
        return "image/x-icon"
    if header.startswith(b"II*\x00") or header.startswith(b"MM\x00*"):
        return "image/tiff"

    # Documents & Executables
    if header.startswith(b"%PDF"):
        return "application/pdf"
    if header.startswith(b"MZ"):
        return "application/x-dosexec"
    if header.startswith(b"\x7fELF"):
        return "application/x-executable"
    if header.startswith(b"\xca\xfe\xba\xbe") or header.startswith(b"\xcf\xfa\xed\xfe"):
        return "application/x-mach-binary"
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        # Check if Office XML (docx, xlsx, pptx) or generic zip
        lower_name = filename.lower()
        if lower_name.endswith(".docx"):
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if lower_name.endswith(".xlsx"):
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if lower_name.endswith(".pptx"):
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return "application/zip"
    if header.startswith(b"Rar!\x1a\x07"):
        return "application/x-rar-compressed"
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"
    if header.startswith(b"\x1f\x8b"):
        return "application/gzip"

    # Text-based formats
    stripped = header.lstrip()
    if stripped.startswith(b"<!DOCTYPE") or stripped.startswith(b"<html") or stripped.startswith(b"<HTML"):
        return "text/html"
    if stripped.startswith(b"<?xml"):
        return "application/xml"
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        try:
            sample = file_bytes[:1024].decode("utf-8", errors="strict")
            if sample.strip().startswith(("{", "[")):
                return "application/json"
        except Exception:
            pass

    # Fallback to extension guess
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or "application/octet-stream"


def _conv_num(val: Any) -> float:
    """Helper to convert Pillow IFDRational or tuple numbers to float."""
    if hasattr(val, "numerator") and hasattr(val, "denominator"):
        return float(val.numerator) / float(val.denominator) if val.denominator != 0 else float(val.numerator)
    if isinstance(val, (tuple, list)) and len(val) == 2:
        return float(val[0]) / float(val[1]) if val[1] != 0 else float(val[0])
    return float(val)


def _make_serializable(val: Any) -> Any:
    """
    Recursively convert any Pillow-specific types (IFDRational, bytes, tuples)
    into plain Python types that are JSON serializable.
    This prevents 'Object of type IFDRational is not JSON serializable' errors.
    """
    # IFDRational: has numerator/denominator attributes like fractions
    if hasattr(val, "numerator") and hasattr(val, "denominator"):
        try:
            denom = float(val.denominator)
            return float(val.numerator) / denom if denom != 0 else float(val.numerator)
        except Exception:
            return str(val)
    # Bytes → decode to string
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="ignore").strip()
        except Exception:
            return str(val)
    # Tuple → convert to list recursively (tuples are not JSON serializable either)
    if isinstance(val, tuple):
        return [_make_serializable(i) for i in val]
    # List → recurse
    if isinstance(val, list):
        return [_make_serializable(i) for i in val]
    # Dict → recurse over values
    if isinstance(val, dict):
        return {str(k): _make_serializable(v) for k, v in val.items()}
    # Plain JSON-safe types
    if isinstance(val, (str, int, float, bool)) or val is None:
        return val
    # Fallback: stringify anything else
    return str(val)


def _dms_to_decimal(dms: Any, ref: Optional[str]) -> Optional[float]:
    """Converts EXIF Degree/Minute/Second coordinates to decimal degrees."""
    try:
        if isinstance(dms, (int, float)):
            deg = float(dms)
        elif isinstance(dms, (tuple, list)):
            d = _conv_num(dms[0])
            m = _conv_num(dms[1]) if len(dms) > 1 else 0.0
            s = _conv_num(dms[2]) if len(dms) > 2 else 0.0
            deg = d + (m / 60.0) + (s / 3600.0)
        else:
            return None
        if ref and str(ref).strip().upper() in ["S", "W"]:
            deg = -deg
        return round(deg, 6)
    except Exception:
        return None


def parse_gps_data(gps_raw: Any) -> Optional[Dict[str, Any]]:
    """
    Extracts and standardizes GPS metadata (lat, lon, altitude, maps links).
    """
    if not isinstance(gps_raw, dict) or not gps_raw:
        return None

    # Map tag IDs to strings
    normalized = {}
    for k, v in gps_raw.items():
        name = GPSTAGS.get(k, k) if isinstance(k, int) else k
        normalized[str(name)] = v

    lat_val = normalized.get("GPSLatitude")
    lat_ref = normalized.get("GPSLatitudeRef", "N")
    lon_val = normalized.get("GPSLongitude")
    lon_ref = normalized.get("GPSLongitudeRef", "E")
    alt_val = normalized.get("GPSAltitude")

    lat = _dms_to_decimal(lat_val, lat_ref) if lat_val is not None else None
    lon = _dms_to_decimal(lon_val, lon_ref) if lon_val is not None else None

    if lat is not None and lon is not None:
        try:
            alt = _conv_num(alt_val) if alt_val is not None else None
        except Exception:
            alt = None

        return {
            "latitude": lat,
            "longitude": lon,
            "latitude_ref": str(lat_ref).strip().upper(),
            "longitude_ref": str(lon_ref).strip().upper(),
            "altitude_m": round(alt, 1) if alt is not None else None,
            "coordinates_text": f"{abs(lat):.4f}° {'N' if lat >= 0 else 'S'}, {abs(lon):.4f}° {'E' if lon >= 0 else 'W'}",
            "google_maps_url": f"https://www.google.com/maps?q={lat},{lon}",
            "osm_url": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}",
        }

    return None


def _parse_pdf_date(raw: str) -> str:
    """Convert PDF date format (e.g. D:20261125005500+05'30') to readable ISO-like string."""
    s = raw.strip()
    m = re.match(
        r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+-].*)?$",
        s,
    )
    if not m:
        return s
    y, mo, d, h, mi, sec, tz = m.groups()
    date_part = f"{y}-{mo or '01'}-{d or '01'}"
    if h is not None:
        time_part = f"{h}:{mi or '00'}:{sec or '00'}"
        tz_clean = (tz or "").replace("'", ":").rstrip(":")
        return f"{date_part} {time_part}{(' ' + tz_clean) if tz_clean else ''}".strip()
    return date_part


def _decode_pdf_bytes_value(raw: bytes) -> str:
    """Decode PDF literal (...) or hex <...> string values, including UTF-16BE BOM."""
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="ignore").replace("\x00", "").strip()
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="ignore").replace("\x00", "").strip()
    return raw.decode("utf-8", errors="ignore").strip()


def _extract_xmp_metadata(raw_bytes: bytes) -> Dict[str, Any]:
    """Extract key metadata fields from embedded XMP XML packets (images or PDFs)."""
    xmp_data: Dict[str, Any] = {}
    start = raw_bytes.find(b"<x:xmpmeta")
    if start == -1:
        start = raw_bytes.find(b"<rdf:RDF")
    if start == -1:
        return xmp_data

    end = raw_bytes.find(b"</x:xmpmeta>", start)
    if end != -1:
        end += len(b"</x:xmpmeta>")
    else:
        end = raw_bytes.find(b"</rdf:RDF>", start)
        if end != -1:
            end += len(b"</rdf:RDF>")
    if end == -1:
        return xmp_data

    xml_slice = raw_bytes[start:end]
    try:
        root = ET.fromstring(xml_slice)
        interesting = {
            "CreateDate", "ModifyDate", "MetadataDate", "DateCreated",
            "DateTimeOriginal", "CreatorTool", "Producer", "Author",
            "creator", "title", "description", "subject", "Keywords",
            "DocumentID", "InstanceID", "Make", "Model", "Lens",
            "GPSLatitude", "GPSLongitude",
        }
        for elem in root.iter():
            tag_local = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            # Attributes on rdf:Description
            for attr_k, attr_v in elem.attrib.items():
                attr_local = attr_k.split("}")[-1] if "}" in attr_k else attr_k
                if attr_local in interesting and attr_v and attr_v.strip():
                    xmp_data[f"XMP:{attr_local}"] = attr_v.strip()
            # Element text or nested rdf:li text
            if tag_local in interesting:
                text_parts = [t.strip() for t in elem.itertext() if t and t.strip()]
                if text_parts:
                    xmp_data[f"XMP:{tag_local}"] = ", ".join(text_parts)
    except Exception:
        pass
    return xmp_data


def extract_document_and_binary_forensics(file_bytes: bytes, mime_type: str, filename: str) -> Dict[str, Any]:
    """
    Extracts forensic metadata from non-image files such as PDFs, ZIP archives, and executables.
    """
    forensics: Dict[str, Any] = {}

    try:
        # PDF Metadata inspection
        if mime_type == "application/pdf" or file_bytes.startswith(b"%PDF"):
            forensics["document_type"] = "PDF Document"
            header_match = re.search(rb"%PDF-(\d+\.\d+)", file_bytes[:1024])
            if header_match:
                forensics["pdf_version"] = header_match.group(1).decode("ascii", errors="ignore")

            # Collect searchable buffers: raw bytes + decompressed FlateDecode streams
            buffers = [file_bytes]
            for stream_match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", file_bytes, re.DOTALL):
                chunk = stream_match.group(1)
                if len(chunk) > 2_000_000:
                    continue
                try:
                    buffers.append(zlib.decompress(chunk))
                except Exception:
                    pass

            combined = b"\n".join(buffers)

            # Extract standard metadata keys (literal (...) or hex <...> strings)
            pdf_keys = [b"Title", b"Author", b"Subject", b"Keywords", b"Creator", b"Producer", b"CreationDate", b"ModDate", b"Trapped"]
            for key in pdf_keys:
                key_name = key.decode("ascii")
                # Literal string: /Key (value) handling escaped parens
                lit_match = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)])*)\)", combined)
                if lit_match:
                    raw_val = lit_match.group(1).replace(rb"\(", b"(").replace(rb"\)", b")").replace(rb"\\", b"\\")
                    val = _decode_pdf_bytes_value(raw_val)
                    if val:
                        forensics[key_name] = _parse_pdf_date(val) if "Date" in key_name else val
                        continue
                # Hex string: /Key <FEFF...>
                hex_match = re.search(rb"/" + key + rb"\s*<([0-9A-Fa-f\s]+)>", combined)
                if hex_match:
                    try:
                        hex_clean = re.sub(rb"\s+", b"", hex_match.group(1))
                        raw_val = bytes.fromhex(hex_clean.decode("ascii"))
                        val = _decode_pdf_bytes_value(raw_val)
                        if val:
                            forensics[key_name] = _parse_pdf_date(val) if "Date" in key_name else val
                    except Exception:
                        pass

            # Extract XMP XML metadata if present in PDF
            xmp_meta = _extract_xmp_metadata(combined)
            for k, v in xmp_meta.items():
                forensics[k] = v

            # Structural & security indicators
            pages = len(re.findall(rb"/Type\s*/Page\b", combined))
            if pages > 0:
                forensics["page_count"] = pages
            forensics["encrypted"] = bool(re.search(rb"/Encrypt\b", combined))
            risk_flags = []
            if re.search(rb"/(?:JavaScript|JS)\b", combined):
                risk_flags.append("JavaScript")
            if re.search(rb"/OpenAction\b", combined):
                risk_flags.append("OpenAction")
            if re.search(rb"/Launch\b", combined):
                risk_flags.append("LaunchAction")
            if re.search(rb"/EmbeddedFile\b", combined):
                risk_flags.append("EmbeddedFile")
            if risk_flags:
                forensics["active_content_flags"] = risk_flags

        # ZIP / Office document structure
        elif "zip" in mime_type or file_bytes.startswith(b"PK\x03\x04"):
            with zipfile.ZipFile(BytesIO(file_bytes), "r") as zf:
                file_list = zf.namelist()
                forensics["archive_type"] = "ZIP Archive"
                forensics["total_archived_files"] = len(file_list)
                forensics["sample_files"] = file_list[:8]

        # Windows PE binary inspection
        elif file_bytes.startswith(b"MZ") and len(file_bytes) >= 0x40:
            e_lfanew = struct.unpack("<I", file_bytes[0x3C:0x40])[0]
            if len(file_bytes) >= e_lfanew + 24 and file_bytes[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                machine = struct.unpack("<H", file_bytes[e_lfanew + 4:e_lfanew + 6])[0]
                arch_map = {0x014C: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xAA64: "ARM64"}
                forensics["binary_type"] = "Windows Portable Executable (PE)"
                forensics["architecture"] = arch_map.get(machine, f"Unknown (0x{machine:04x})")
                timestamp = struct.unpack("<I", file_bytes[e_lfanew + 8:e_lfanew + 12])[0]
                if timestamp > 0:
                    forensics["compile_timestamp"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except Exception as e:
        logger.debug("Non-image forensic extraction exception on %s: %s", filename, e)

    return forensics


def extract_exif_metadata(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """
    Reads dimensions, format, and EXIF tags from image files using Pillow.
    Handles base IFD, Exif sub-IFD, and GPS IFD data.
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
        stream = BytesIO(file_bytes)
        with Image.open(stream) as img:
            result["is_image"] = True
            result["format"] = img.format
            result["width"] = img.width
            result["height"] = img.height

            # Parse EXIF tags using getexif()
            exif_dict: Dict[str, Any] = {}
            gps_raw: Dict[str, Any] = {}

            exif_data = img.getexif()
            if exif_data:
                for tag, value in exif_data.items():
                    tag_name = TAGS.get(tag, str(tag))
                    if tag_name == "GPSInfo" and isinstance(value, dict):
                        gps_raw.update(value)

                    # Deep-convert any IFDRational / bytes / tuples to JSON-safe types
                    exif_dict[str(tag_name)] = _make_serializable(value)

                # Also inspect sub-IFD for GPSInfo (IFD 0x8825 / 34853)
                try:
                    gps_ifd = exif_data.get_ifd(IFD.GPSInfo)
                    if gps_ifd:
                        for k, v in gps_ifd.items():
                            gps_raw[k] = v
                except Exception:
                    pass

                # Also inspect sub-IFD for Exif tags (IFD 0x8769 / 34665)
                try:
                    exif_sub = exif_data.get_ifd(IFD.Exif)
                    if exif_sub:
                        for k, v in exif_sub.items():
                            sub_name = TAGS.get(k, str(k))
                            if str(sub_name) not in exif_dict:
                                exif_dict[str(sub_name)] = _make_serializable(v)
                except Exception:
                    pass

            # Legacy fallback: _getexif() for older JPEG structures
            if not exif_dict and hasattr(img, "_getexif"):
                legacy_exif = img._getexif()
                if legacy_exif:
                    for tag, value in legacy_exif.items():
                        tag_name = TAGS.get(tag, str(tag))
                        if tag_name == "GPSInfo" and isinstance(value, dict):
                            gps_raw.update(value)
                        exif_dict[str(tag_name)] = _make_serializable(value)

            # Extract PNG / WebP / GIF info & text chunks (e.g. Creation Time, Software, XMP)
            if getattr(img, "info", None):
                for info_k, info_v in img.info.items():
                    if info_k in ("icc_profile", "exif"):
                        if info_k == "icc_profile":
                            exif_dict["ICCProfile"] = f"Present ({len(info_v)} bytes)" if isinstance(info_v, (bytes, bytearray)) else "Present"
                        continue
                    if info_k == "XML:com.adobe.xmp" and isinstance(info_v, (str, bytes)):
                        xmp_bytes = info_v.encode("utf-8", errors="ignore") if isinstance(info_v, str) else info_v
                        exif_dict.update(_extract_xmp_metadata(xmp_bytes))
                        continue
                    if str(info_k) not in exif_dict:
                        exif_dict[str(info_k)] = _make_serializable(info_v)

            # Extract embedded XMP packet anywhere in image bytes (JPEG APP1, WebP, TIFF)
            xmp_meta = _extract_xmp_metadata(file_bytes)
            for k, v in xmp_meta.items():
                if k not in exif_dict:
                    exif_dict[k] = v

            result["exif"] = exif_dict
            # Sanitize gps_raw too — IFDRational values may still be present in raw GPS dict
            result["gps_raw"] = {str(k): _make_serializable(v) for k, v in gps_raw.items()}

    except Exception as e:
        logger.debug("Pillow failed to open image %s: %s", filename, e)
        result["error"] = f"Not a parsable image or error: {str(e)}"

    return result


def analyze_file(db: Session, investigation_id: str, filename: str, file_bytes: bytes) -> Dict[str, Any]:
    """
    Main File Intelligence Scanner.
    Processes uploaded file, extracts hashes, MIME type, EXIF metadata, document/binary forensics,
    queries threat intelligence reputation, and saves findings and IOCs.
    """
    logger.info("Starting file intelligence scan for filename: %s", filename)

    now_iso = datetime.now(timezone.utc).isoformat()
    hashes = calculate_hashes(file_bytes)
    file_size_bytes = len(file_bytes)
    file_size_human = format_file_size(file_size_bytes)
    mime_type = detect_mime_type(file_bytes, filename)

    metadata = extract_exif_metadata(file_bytes, filename)
    is_image = metadata["is_image"]
    raw_exif = metadata.get("exif", {})
    raw_gps = metadata.get("gps_raw", {})

    # Build standardized EXIF metadata structure expected by Frontend
    has_exif = bool(raw_exif and any(k not in ("error",) for k in raw_exif.keys()))
    camera_make = raw_exif.get("Make") or raw_exif.get("XMP:Make")
    camera_model = raw_exif.get("Model") or raw_exif.get("XMP:Model")
    datetime_original = (
        raw_exif.get("DateTimeOriginal")
        or raw_exif.get("DateTimeDigitized")
        or raw_exif.get("DateTime")
        or raw_exif.get("XMP:DateTimeOriginal")
        or raw_exif.get("XMP:CreateDate")
        or raw_exif.get("XMP:DateCreated")
        or raw_exif.get("Creation Time")
        or raw_exif.get("date:create")
    )
    software = (
        raw_exif.get("Software")
        or raw_exif.get("XMP:CreatorTool")
        or raw_exif.get("CreatorTool")
    )
    gps_info = parse_gps_data(raw_gps) if raw_gps else None

    # If GPS info wasn't in raw_gps, check if it was parsed as string/dict in raw_exif
    if not gps_info and "GPSInfo" in raw_exif:
        gps_info = parse_gps_data(raw_exif.get("GPSInfo"))

    exif_metadata = {
        "has_exif": has_exif,
        "is_image": is_image,
        "format": metadata.get("format"),
        "dimensions": f"{metadata.get('width')} x {metadata.get('height')}" if metadata.get("width") else None,
        "camera_make": str(camera_make) if camera_make else None,
        "camera_model": str(camera_model) if camera_model else None,
        "datetime_original": str(datetime_original) if datetime_original else None,
        "software": str(software) if software else None,
        "gps_info": gps_info,
        "all_tags": raw_exif,
    }

    # Extract non-image document & binary forensics
    non_image_forensics = extract_document_and_binary_forensics(file_bytes, mime_type, filename)

    # Query Threat Intelligence (VirusTotal) on file SHA-256
    vt_result = check_virustotal(hashes["sha256"], target_type="hash")
    threat_intel_summary: Dict[str, Any] = {
        "available": False,
        "verdict": "clean",
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 0,
        "undetected_count": 0,
        "reputation_score": 0.0,
        "detection_ratio": "0/0",
    }

    reputation_score = 0.0
    if vt_result and "data" in vt_result:
        stats = vt_result["data"].get("attributes", {}).get("last_analysis_stats", {})
        reputation = vt_result["data"].get("attributes", {}).get("reputation", 0)
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + sus + harm + undet

        verdict = "clean"
        if mal >= 3:
            verdict = "malicious"
            reputation_score = 90.0
        elif mal > 0 or sus >= 2:
            verdict = "suspicious"
            reputation_score = 50.0

        threat_intel_summary = {
            "available": True,
            "verdict": verdict,
            "malicious_count": mal,
            "suspicious_count": sus,
            "harmless_count": harm,
            "undetected_count": undet,
            "reputation_score": reputation,
            "detection_ratio": f"{mal}/{total}" if total > 0 else "0/0",
        }

    finding_id = str(uuid.uuid4())

    scan_result = {
        "finding_id": finding_id,
        "target": filename,
        "filename": filename,  # Required by frontend
        "file_size_bytes": file_size_bytes,
        "file_size_human": file_size_human,  # Required by frontend
        "mime_type": mime_type,  # Required by frontend
        "scanned_at": now_iso,
        "analyzed_at": now_iso,  # Required by frontend
        "hashes": hashes,
        "image_metadata": metadata,  # Preserved for backward compatibility (test_phase6.py)
        "exif_metadata": exif_metadata,  # Structured for frontend
        "document_forensics": non_image_forensics,
        "threat_intel": threat_intel_summary,
        "summary": {
            "file_size": file_size_bytes,
            "file_size_human": file_size_human,
            "sha256": hashes["sha256"],
            "is_image": is_image,
            "image_format": metadata.get("format"),
            "mime_type": mime_type,
            "has_exif": has_exif,
            "threat_verdict": threat_intel_summary["verdict"],
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

    # Store SHA-256 hash as an IOC with reputation score
    sha256_hash = hashes["sha256"]
    ioc_hash = db.query(IOC).filter(IOC.value == sha256_hash).first()
    if not ioc_hash:
        db.add(IOC(value=sha256_hash, type="hash", source="file_module", reputation_score=reputation_score))
    elif reputation_score > ioc_hash.reputation_score:
        ioc_hash.reputation_score = reputation_score

    db.commit()
    db.refresh(finding)

    return scan_result
