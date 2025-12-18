"""
CIP-010 Configuration Comparison Engine

This module handles deep comparison of JSON configurations,
including the set-based array comparison and inline diff highlighting.

Ported from the JavaScript implementation in the HTML prototype.
"""
from typing import Any, Optional
from dataclasses import dataclass, field
from enum import Enum
import json
import hashlib


class ChangeType(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    ARRAY_MODIFIED = "array_modified"


@dataclass
class ConfigChange:
    """Represents a single configuration change."""
    path: str
    change_type: ChangeType
    old_value: Any = None
    new_value: Any = None
    
    # For array modifications
    items_added: list = field(default_factory=list)
    items_removed: list = field(default_factory=list)
    
    # Computed signature for grouping identical changes
    signature: str = ""
    
    def __post_init__(self):
        """Compute signature after initialization."""
        if not self.signature:
            self.signature = self.compute_signature()
    
    def compute_signature(self) -> str:
        """
        Compute a signature for grouping identical changes across assets.
        Two changes with the same signature can be approved/rejected together.
        """
        if self.change_type == ChangeType.ARRAY_MODIFIED:
            # Include added/removed items in signature
            sig_parts = [
                self.path,
                self.change_type.value,
                f"+{len(self.items_added)}",
                f"-{len(self.items_removed)}",
                json.dumps(sorted([_object_to_key(i) for i in self.items_added])),
                json.dumps(sorted([_object_to_key(i) for i in self.items_removed]))
            ]
        else:
            sig_parts = [
                self.path,
                self.change_type.value,
                json.dumps(self.old_value, sort_keys=True) if self.old_value is not None else "null",
                json.dumps(self.new_value, sort_keys=True) if self.new_value is not None else "null"
            ]
        
        sig_str = "|".join(str(p) for p in sig_parts)
        return hashlib.sha256(sig_str.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            "path": self.path,
            "change_type": self.change_type.value,
            "signature": self.signature
        }
        
        if self.change_type == ChangeType.ARRAY_MODIFIED:
            result["items_added"] = self.items_added
            result["items_removed"] = self.items_removed
            result["added_count"] = len(self.items_added)
            result["removed_count"] = len(self.items_removed)
        else:
            if self.old_value is not None:
                result["old_value"] = self.old_value
            if self.new_value is not None:
                result["new_value"] = self.new_value
        
        return result


@dataclass
class ComparisonResult:
    """Result of comparing two configurations."""
    changes: list[ConfigChange] = field(default_factory=list)
    old_hash: str = ""
    new_hash: str = ""
    is_identical: bool = True
    
    @property
    def change_count(self) -> int:
        return len(self.changes)
    
    @property
    def changes_by_signature(self) -> dict[str, ConfigChange]:
        """Group changes by signature for bulk operations."""
        return {c.signature: c for c in self.changes}
    
    def to_dict(self) -> dict:
        return {
            "is_identical": self.is_identical,
            "change_count": self.change_count,
            "old_hash": self.old_hash,
            "new_hash": self.new_hash,
            "changes": [c.to_dict() for c in self.changes]
        }


def _try_parse_array_string(value: str) -> Optional[list]:
    """
    Try to parse a string that might be a Python-style array representation.
    Returns the parsed list or None if not parseable.

    This handles strings like "[{'protocol': 'tcp', 'port': 22}, ...]"
    """
    if not isinstance(value, str):
        return None

    trimmed = value.strip()
    if not (trimmed.startswith('[') and trimmed.endswith(']')):
        return None

    # Try direct JSON parse first
    try:
        parsed = json.loads(trimmed)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try converting Python-style syntax to JSON
    try:
        # Replace Python-style quotes and keywords
        json_str = trimmed.replace("'", '"')
        json_str = json_str.replace('True', 'true')
        json_str = json_str.replace('False', 'false')
        json_str = json_str.replace('None', 'null')
        parsed = json.loads(json_str)
        if isinstance(parsed, list):
            return parsed
    except json.JSONDecodeError:
        pass

    return None


def _object_to_key(obj: Any) -> str:
    """
    Convert any object to a consistent string key for set-based comparison.
    This handles nested objects and arrays.
    """
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if isinstance(obj, (int, float, str)):
        return str(obj)
    if isinstance(obj, list):
        # Sort array elements for consistent comparison
        return "[" + ",".join(sorted(_object_to_key(item) for item in obj)) + "]"
    if isinstance(obj, dict):
        # Sort keys and recurse
        parts = []
        for key in sorted(obj.keys()):
            parts.append(f"{key}:{_object_to_key(obj[key])}")
        return "{" + ",".join(parts) + "}"
    return str(obj)


def _compare_arrays_as_sets(old_arr: list, new_arr: list, path: str) -> list[ConfigChange]:
    """
    Compare two arrays as sets to find added/removed items.
    This is the key logic for comparing things like ports_services_string.
    
    Order doesn't matter - we only care about what items exist.
    """
    # Build sets using our consistent key function
    old_keys = {}
    for item in old_arr:
        key = _object_to_key(item)
        old_keys[key] = item
    
    new_keys = {}
    for item in new_arr:
        key = _object_to_key(item)
        new_keys[key] = item
    
    # Find differences
    added = []
    removed = []
    
    for key, item in old_keys.items():
        if key not in new_keys:
            removed.append(item)
    
    for key, item in new_keys.items():
        if key not in old_keys:
            added.append(item)
    
    # No changes
    if not added and not removed:
        return []
    
    return [ConfigChange(
        path=path,
        change_type=ChangeType.ARRAY_MODIFIED,
        items_added=added,
        items_removed=removed
    )]


def deep_compare(old_obj: Any, new_obj: Any, path: str = "") -> list[ConfigChange]:
    """
    Recursively compare two objects and return all differences.
    
    This handles:
    - Nested objects
    - Arrays (using set-based comparison)
    - Primitive values
    - Added/removed keys
    """
    changes = []
    
    # Handle None/null cases
    if old_obj is None and new_obj is None:
        return []
    
    if old_obj is None:
        return [ConfigChange(
            path=path or "root",
            change_type=ChangeType.ADDED,
            new_value=new_obj
        )]
    
    if new_obj is None:
        return [ConfigChange(
            path=path or "root",
            change_type=ChangeType.REMOVED,
            old_value=old_obj
        )]
    
    # Type mismatch
    if type(old_obj) != type(new_obj):
        return [ConfigChange(
            path=path or "root",
            change_type=ChangeType.MODIFIED,
            old_value=old_obj,
            new_value=new_obj
        )]
    
    # Both are lists - use set comparison
    if isinstance(old_obj, list) and isinstance(new_obj, list):
        return _compare_arrays_as_sets(old_obj, new_obj, path or "root")
    
    # Both are dicts - recurse
    if isinstance(old_obj, dict) and isinstance(new_obj, dict):
        all_keys = set(old_obj.keys()) | set(new_obj.keys())
        
        for key in all_keys:
            new_path = f"{path}.{key}" if path else key
            
            if key not in old_obj:
                changes.append(ConfigChange(
                    path=new_path,
                    change_type=ChangeType.ADDED,
                    new_value=new_obj[key]
                ))
            elif key not in new_obj:
                changes.append(ConfigChange(
                    path=new_path,
                    change_type=ChangeType.REMOVED,
                    old_value=old_obj[key]
                ))
            else:
                changes.extend(deep_compare(old_obj[key], new_obj[key], new_path))
        
        return changes
    
    # Primitive comparison
    if old_obj != new_obj:
        # Check if both are strings that look like arrays (Python repr format)
        # This handles fields like ports_services_string that store arrays as strings
        if isinstance(old_obj, str) and isinstance(new_obj, str):
            old_arr = _try_parse_array_string(old_obj)
            new_arr = _try_parse_array_string(new_obj)
            if old_arr is not None and new_arr is not None:
                # Both are parseable arrays - use set comparison
                return _compare_arrays_as_sets(old_arr, new_arr, path or "root")

        return [ConfigChange(
            path=path or "root",
            change_type=ChangeType.MODIFIED,
            old_value=old_obj,
            new_value=new_obj
        )]

    return []


def compute_config_hash(config: dict) -> str:
    """
    Compute a SHA-256 hash of a configuration for quick comparison.
    Configurations with the same hash are identical.
    """
    json_str = json.dumps(config, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode()).hexdigest()


def compare_configurations(old_config: dict, new_config: dict) -> ComparisonResult:
    """
    Main entry point for comparing two configurations.
    
    Args:
        old_config: The baseline/previous configuration
        new_config: The new/current configuration
    
    Returns:
        ComparisonResult with all detected changes
    """
    old_hash = compute_config_hash(old_config)
    new_hash = compute_config_hash(new_config)
    
    # Quick check - if hashes match, configs are identical
    if old_hash == new_hash:
        return ComparisonResult(
            changes=[],
            old_hash=old_hash,
            new_hash=new_hash,
            is_identical=True
        )
    
    # Perform deep comparison
    changes = deep_compare(old_config, new_config)
    
    return ComparisonResult(
        changes=changes,
        old_hash=old_hash,
        new_hash=new_hash,
        is_identical=len(changes) == 0
    )


def create_inline_diff(old_str: str, new_str: str) -> dict:
    """
    Create inline diff highlighting showing what changed between two strings.
    Returns dict with 'old_html' and 'new_html' containing highlighted versions.
    
    This is used for the UI to show exactly which characters changed.
    """
    old_str = str(old_str)
    new_str = str(new_str)
    
    # Find common prefix
    prefix_len = 0
    while (prefix_len < len(old_str) and 
           prefix_len < len(new_str) and 
           old_str[prefix_len] == new_str[prefix_len]):
        prefix_len += 1
    
    # Find common suffix
    suffix_len = 0
    while (suffix_len < (len(old_str) - prefix_len) and 
           suffix_len < (len(new_str) - prefix_len) and
           old_str[len(old_str) - 1 - suffix_len] == new_str[len(new_str) - 1 - suffix_len]):
        suffix_len += 1
    
    prefix = old_str[:prefix_len]
    suffix = old_str[len(old_str) - suffix_len:] if suffix_len > 0 else ""
    old_middle = old_str[prefix_len:len(old_str) - suffix_len] if suffix_len > 0 else old_str[prefix_len:]
    new_middle = new_str[prefix_len:len(new_str) - suffix_len] if suffix_len > 0 else new_str[prefix_len:]
    
    return {
        "prefix": prefix,
        "suffix": suffix,
        "old_changed": old_middle,
        "new_changed": new_middle,
        "old_html": f"{prefix}<span class='hl-removed'>{old_middle}</span>{suffix}" if old_middle else f"{prefix}{suffix}",
        "new_html": f"{prefix}<span class='hl-added'>{new_middle}</span>{suffix}" if new_middle else f"{prefix}{suffix}"
    }


def format_value_compact(value: Any) -> str:
    """Format a value for display in a compact way."""
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(',', ':'))
    return str(value)


def group_changes_by_signature(changes_with_assets: list[tuple[str, ConfigChange]]) -> dict:
    """
    Group changes across multiple assets by their signature.
    
    This enables the bulk approval feature where identical changes
    across multiple assets can be approved/rejected together.
    
    Args:
        changes_with_assets: List of (asset_name, ConfigChange) tuples
    
    Returns:
        Dict mapping signature to {change: ConfigChange, assets: [asset_names]}
    """
    grouped = {}
    
    for asset_name, change in changes_with_assets:
        sig = change.signature
        if sig not in grouped:
            grouped[sig] = {
                "change": change,
                "assets": []
            }
        grouped[sig]["assets"].append(asset_name)
    
    return grouped
