# Fiducia v4.0.6
"""
Core package for CIP-010 Baseline Engine.
Contains comparison logic and file parsing utilities.
"""
from core.comparison import (
    compare_configurations,
    deep_compare,
    compute_config_hash,
    create_inline_diff,
    group_changes_by_signature,
    format_value_compact,
    ConfigChange,
    ComparisonResult,
    ChangeType
)
from core.file_parser import (
    parse_filename,
    parse_json_file,
    parse_json_content,
    parse_json_dict,
    extract_metadata,
    ParsedFile
)

__all__ = [
    "compare_configurations",
    "deep_compare", 
    "compute_config_hash",
    "create_inline_diff",
    "group_changes_by_signature",
    "format_value_compact",
    "ConfigChange",
    "ComparisonResult",
    "ChangeType",
    "parse_filename",
    "parse_json_file",
    "parse_json_content",
    "parse_json_dict",
    "extract_metadata",
    "ParsedFile"
]
