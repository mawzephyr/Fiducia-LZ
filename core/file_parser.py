"""
File parsing utilities for CIP-010 Baseline Engine.

Assets are identified by FQDN from within the JSON file.
Timestamps are extracted to ensure we only compare newer files.
"""
import re
import json
from pathlib import Path
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ParsedFile:
    """Result of parsing a baseline JSON file."""
    asset_name: str  # Now derived from FQDN
    config: dict
    filename: str
    file_path: Optional[str] = None
    
    # Extracted metadata from config
    fqdn: Optional[str] = None
    version: Optional[str] = None
    capture_timestamp: Optional[datetime] = None  # When the baseline was captured


def extract_metadata(config: dict) -> dict:
    """
    Extract common metadata fields from a configuration.
    
    Looks for (case-insensitive):
    - fqdn, FQDN, hostname - for asset identification
    - version, Version - software version
    - capture_date, timestamp, date, scan_date - when captured
    """
    metadata = {
        "fqdn": None,
        "version": None,
        "capture_timestamp": None
    }
    
    # Look for FQDN (primary identifier)
    for key in ['fqdn', 'FQDN', 'Fqdn', 'hostname', 'Hostname', 'HOSTNAME', 'host', 'Host', 
                'computer_name', 'ComputerName', 'computer', 'name', 'Name', 'asset_name', 'AssetName']:
        if key in config:
            value = config[key]
            if value and isinstance(value, str) and value.strip():
                metadata["fqdn"] = str(value).strip()
                break
    
    # Look for version
    for key in ['version', 'Version', 'VERSION', 'ver', 'Ver', 'os_version', 'OsVersion']:
        if key in config:
            metadata["version"] = str(config[key])
            break
    
    # Look for capture timestamp
    timestamp_keys = [
        'capture_date', 'CaptureDate', 'captured_at', 'CapturedAt',
        'timestamp', 'Timestamp', 'TIMESTAMP',
        'date', 'Date', 'DATE',
        'scan_date', 'ScanDate', 'scan_time', 'ScanTime',
        'collection_date', 'CollectionDate',
        'baseline_date', 'BaselineDate',
        'created', 'Created', 'created_at', 'CreatedAt'
    ]
    
    for key in timestamp_keys:
        if key in config:
            ts = parse_timestamp(config[key])
            if ts:
                metadata["capture_timestamp"] = ts
                break
    
    return metadata


def parse_timestamp(value) -> Optional[datetime]:
    """
    Parse various timestamp formats into datetime.
    
    Supports:
    - ISO format: 2024-01-15T10:30:00
    - Date only: 2024-01-15
    - US format: 01/15/2024, 1/15/2024
    - With time: 2024-01-15 10:30:00
    - Unix timestamp (int or float)
    """
    if value is None:
        return None
    
    if isinstance(value, datetime):
        return value
    
    if isinstance(value, (int, float)):
        # Unix timestamp - use UTC
        try:
            return datetime.utcfromtimestamp(value)
        except:
            return None
    
    if not isinstance(value, str):
        return None
    
    value = value.strip()
    
    # Common formats to try
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y",
        "%Y%m%d%H%M%S",
        "%Y%m%d",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    
    return None


def derive_asset_name_from_fqdn(fqdn: str) -> str:
    """
    Derive a clean asset name from FQDN.
    
    Examples:
        server01.tva.gov -> server01
        DESKTOP-ABC123.corp.tva.gov -> DESKTOP-ABC123
        10.1.2.3 -> 10.1.2.3 (IP addresses kept as-is)
    """
    if not fqdn:
        return "unknown"
    
    # If it's an IP address, use as-is
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', fqdn):
        return fqdn
    
    # Take the first part before the first dot (hostname portion)
    parts = fqdn.split('.')
    return parts[0] if parts else fqdn


def parse_json_file(file_path: str) -> Optional[ParsedFile]:
    """
    Parse a JSON file from disk.
    
    Args:
        file_path: Path to the JSON file
    
    Returns:
        ParsedFile object or None if parsing fails
    """
    path = Path(file_path)
    
    if not path.exists():
        return None
    
    if not path.suffix.lower() == '.json':
        return None
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error parsing {file_path}: {e}")
        return None
    
    metadata = extract_metadata(config)
    
    # Use FQDN as the primary identifier, fall back to filename
    if metadata["fqdn"]:
        asset_name = metadata["fqdn"]  # Use full FQDN as asset_name for uniqueness
    else:
        # Fallback: derive from filename
        base_name = path.stem  # filename without extension
        asset_name = re.sub(r'\d+$', '', base_name)  # Remove trailing digits
    
    return ParsedFile(
        asset_name=asset_name,
        config=config,
        filename=path.name,
        file_path=str(path.absolute()),
        fqdn=metadata["fqdn"],
        version=metadata["version"],
        capture_timestamp=metadata["capture_timestamp"]
    )


def parse_json_content(content: str, filename: str) -> Optional[ParsedFile]:
    """
    Parse JSON content directly (for API uploads).
    
    Args:
        content: JSON string content
        filename: Original filename (used as fallback if no FQDN)
    
    Returns:
        ParsedFile object or None if parsing fails
    """
    try:
        config = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON content: {e}")
        return None
    
    metadata = extract_metadata(config)
    
    # Use FQDN as the primary identifier, fall back to filename
    if metadata["fqdn"]:
        asset_name = metadata["fqdn"]
    else:
        # Fallback: derive from filename
        base_name = filename.replace('.json', '').replace('.JSON', '')
        asset_name = re.sub(r'\d+$', '', base_name)
    
    return ParsedFile(
        asset_name=asset_name,
        config=config,
        filename=filename,
        fqdn=metadata["fqdn"],
        version=metadata["version"],
        capture_timestamp=metadata["capture_timestamp"]
    )


def parse_json_dict(config: dict, filename: str) -> ParsedFile:
    """
    Create ParsedFile from an already-parsed dict.
    
    Args:
        config: Already parsed JSON dict
        filename: Original filename (used as fallback if no FQDN)
    
    Returns:
        ParsedFile object
    """
    metadata = extract_metadata(config)
    
    # Use FQDN as the primary identifier, fall back to filename
    if metadata["fqdn"]:
        asset_name = metadata["fqdn"]
    else:
        base_name = filename.replace('.json', '').replace('.JSON', '')
        asset_name = re.sub(r'\d+$', '', base_name)
    
    return ParsedFile(
        asset_name=asset_name,
        config=config,
        filename=filename,
        fqdn=metadata["fqdn"],
        version=metadata["version"],
        capture_timestamp=metadata["capture_timestamp"]
    )


# Keep for backwards compatibility but mark as deprecated
def parse_filename(filename: str) -> Tuple[str, str]:
    """
    DEPRECATED: Parse filename for asset name.
    Now using FQDN from file content instead.
    """
    base_name = filename.replace('.json', '').replace('.JSON', '')
    match = re.match(r'^(.+?)(\d+)$', base_name)
    if match:
        return match.group(1), match.group(2)
    return base_name, "1"
