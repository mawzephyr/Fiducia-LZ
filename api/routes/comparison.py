"""
Comparison routes for CIP-010 Baseline Engine.

Provides the manual baseline comparison feature.
"""
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
import json

from core import compare_configurations, create_inline_diff, ComparisonResult
from api.schemas import ComparisonRequest, ComparisonResponse, ConfigChangeSchema
from api.routes.auth import get_current_user, User

router = APIRouter()


@router.post("", response_model=ComparisonResponse)
async def compare_configs(
    request: ComparisonRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Compare two configurations and return differences.
    """
    result = compare_configurations(request.old_config, request.new_config)
    
    return ComparisonResponse(
        is_identical=result.is_identical,
        change_count=result.change_count,
        old_hash=result.old_hash,
        new_hash=result.new_hash,
        changes=[
            ConfigChangeSchema(
                path=c.path,
                change_type=c.change_type.value,
                old_value=c.old_value,
                new_value=c.new_value,
                items_added=c.items_added if c.items_added else None,
                items_removed=c.items_removed if c.items_removed else None,
                added_count=len(c.items_added) if c.items_added else None,
                removed_count=len(c.items_removed) if c.items_removed else None,
                signature=c.signature
            )
            for c in result.changes
        ]
    )


@router.post("/files")
async def compare_files(
    before_file: UploadFile = File(...),
    after_file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Compare two uploaded JSON files.
    """
    # Validate file types
    if not before_file.filename.lower().endswith('.json'):
        raise HTTPException(status_code=400, detail="Before file must be JSON")
    if not after_file.filename.lower().endswith('.json'):
        raise HTTPException(status_code=400, detail="After file must be JSON")
    
    try:
        before_content = await before_file.read()
        before_config = json.loads(before_content.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON in before file: {e}")
    
    try:
        after_content = await after_file.read()
        after_config = json.loads(after_content.decode('utf-8'))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON in after file: {e}")
    
    result = compare_configurations(before_config, after_config)
    
    return {
        "before_file": before_file.filename,
        "after_file": after_file.filename,
        "is_identical": result.is_identical,
        "change_count": result.change_count,
        "changes": [c.to_dict() for c in result.changes],
        "report": _generate_manual_report(
            before_file.filename,
            after_file.filename,
            result
        )
    }


@router.post("/inline-diff")
async def get_inline_diff(
    old_value: str,
    new_value: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get inline diff highlighting for two string values.

    Returns HTML with highlighted changes.
    """
    diff = create_inline_diff(old_value, new_value)
    return diff


def _generate_manual_report(before_filename: str, after_filename: str, result: ComparisonResult) -> str:
    """Generate a text report for manual comparison."""
    from datetime import datetime
    from config import settings
    
    lines = [
        "=" * 70,
        "MANUAL FILE COMPARISON REPORT",
        f"CIP-010 Baseline Engine v{settings.APP_VERSION}",
        "=" * 70,
        "",
        f"Timestamp:        {datetime.utcnow().isoformat()}",
        f"Before File:      {before_filename}",
        f"After File:       {after_filename}",
        "",
    ]
    
    if result.is_identical:
        lines.extend([
            "-" * 40,
            "RESULT: NO DIFFERENCES FOUND",
            "-" * 40,
            "",
            "The two files are identical.",
        ])
    else:
        lines.extend([
            "-" * 40,
            f"RESULT: {result.change_count} DIFFERENCE(S) FOUND",
            "-" * 40,
            "",
        ])
        
        for i, change in enumerate(result.changes, 1):
            lines.extend([
                f"Change #{i}",
                f"  Field:       {change.path}",
                f"  Type:        {change.change_type.value.upper()}",
            ])
            
            if change.change_type.value == "array_modified":
                if change.items_added:
                    lines.append(f"  Added:       {len(change.items_added)} item(s)")
                    for item in change.items_added:
                        lines.append(f"    + {json.dumps(item)}")
                if change.items_removed:
                    lines.append(f"  Removed:     {len(change.items_removed)} item(s)")
                    for item in change.items_removed:
                        lines.append(f"    - {json.dumps(item)}")
            else:
                if change.old_value is not None:
                    lines.append(f"  Old Value:   {json.dumps(change.old_value)}")
                if change.new_value is not None:
                    lines.append(f"  New Value:   {json.dumps(change.new_value)}")
            
            lines.append("")
    
    lines.extend([
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ])
    
    return "\n".join(lines)
