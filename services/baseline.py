"""
Baseline computation service for CIP-010 Baseline Engine.

This module handles the field-level baseline construction logic.
The effective baseline is computed from the change history, not just snapshots.

Key concept:
- Approved changes → new value incorporated into baseline
- Rejected changes → old baseline value preserved
- Investigation/Pending → old baseline value shown (pending decision)
"""
import json
import copy
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime

from sqlalchemy.orm import Session

from database import Asset, BaselineSnapshot, Change, ChangeStatus


class FieldStatus:
    """Status indicators for baseline fields."""
    BASELINE = "baseline"           # Original baseline value, no changes
    APPROVED = "approved"           # New value approved and incorporated
    REJECTED = "rejected"           # Change rejected, baseline preserved
    INVESTIGATION = "investigation" # Under investigation, baseline shown
    PENDING = "pending"             # Pending review, baseline shown


def compute_effective_baseline(
    db: Session,
    asset_id: int,
    include_field_status: bool = True
) -> Dict[str, Any]:
    """
    Compute the effective baseline for an asset based on change history.

    The effective baseline is:
    - Start with the promoted baseline (is_current_baseline=True)
    - Apply all APPROVED changes (use new values)
    - For REJECTED changes, baseline value is preserved (no action needed)
    - For PENDING/INVESTIGATION, baseline value shown (no action needed)

    Args:
        db: Database session
        asset_id: The asset ID
        include_field_status: If True, include metadata about each field's status

    Returns:
        {
            "config": { ... effective baseline config ... },
            "field_statuses": { "field_path": "approved|rejected|investigation|pending|baseline" },
            "baseline_snapshot_id": int,
            "baseline_promoted_at": datetime,
            "has_pending_changes": bool,
            "pending_count": int,
            "investigation_count": int
        }
    """
    # Get the current promoted baseline
    current_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == True
    ).first()

    if not current_baseline:
        # No baseline yet - check for pending initial baseline
        pending_baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset_id,
            BaselineSnapshot.promoted_at == None
        ).order_by(BaselineSnapshot.captured_at.desc()).first()

        if pending_baseline:
            return {
                "config": json.loads(pending_baseline.config_json),
                "field_statuses": {},
                "field_tickets": {},
                "baseline_snapshot_id": pending_baseline.id,
                "baseline_promoted_at": None,
                "ticket_number": pending_baseline.ticket_number,
                "is_initial_baseline": True,
                "has_pending_changes": False,
                "pending_count": 0,
                "investigation_count": 0
            }
        return {
            "config": None,
            "field_statuses": {},
            "field_tickets": {},
            "baseline_snapshot_id": None,
            "baseline_promoted_at": None,
            "ticket_number": None,
            "has_pending_changes": False,
            "pending_count": 0,
            "investigation_count": 0
        }

    # Start with the promoted baseline config
    effective_config = json.loads(current_baseline.config_json)
    field_statuses = {}

    # Start with field tickets from baseline (persisted from finalized changes)
    field_tickets = {}
    if current_baseline.field_tickets_json:
        field_tickets = json.loads(current_baseline.field_tickets_json)

    # Track when each field's current value was first seen
    # Default to baseline promotion date for all fields
    baseline_promoted_at = current_baseline.promoted_at.isoformat() if current_baseline.promoted_at else None
    field_first_seen = {}  # Will be populated: field_path -> ISO date string

    # Get all changes for this asset (not deleted/finalized)
    changes = db.query(Change).filter(
        Change.asset_id == asset_id
    ).all()

    pending_count = 0
    investigation_count = 0

    for change in changes:
        field_path = change.field_path

        if change.status == ChangeStatus.APPROVED:
            # Apply approved change - use new value
            if change.new_value:
                new_val = json.loads(change.new_value)
                _set_nested_value(effective_config, field_path, new_val)
            elif change.items_added or change.items_removed:
                # Array modification - apply additions and removals
                _apply_array_change(effective_config, field_path, change)
            field_statuses[field_path] = FieldStatus.APPROVED
            if change.ticket_number:
                field_tickets[field_path] = change.ticket_number
            # Track when this value was first seen (when the change was approved)
            if change.status_changed_at:
                field_first_seen[field_path] = change.status_changed_at.isoformat()

        elif change.status == ChangeStatus.REJECTED:
            # Rejected - baseline value preserved (already there)
            # Just mark the field status
            field_statuses[field_path] = FieldStatus.REJECTED
            if change.ticket_number:
                field_tickets[field_path] = change.ticket_number

        elif change.status == ChangeStatus.INVESTIGATION:
            # Under investigation - baseline value shown
            field_statuses[field_path] = FieldStatus.INVESTIGATION
            investigation_count += 1
            if change.ticket_number:
                field_tickets[field_path] = change.ticket_number

        elif change.status == ChangeStatus.PENDING:
            # Pending review - baseline value shown
            field_statuses[field_path] = FieldStatus.PENDING
            pending_count += 1
            if change.ticket_number:
                field_tickets[field_path] = change.ticket_number

    return {
        "config": effective_config,
        "field_statuses": field_statuses if include_field_status else {},
        "field_tickets": field_tickets if include_field_status else {},
        "field_first_seen": field_first_seen if include_field_status else {},
        "baseline_promoted_at": baseline_promoted_at,
        "baseline_snapshot_id": current_baseline.id,
        "ticket_number": current_baseline.ticket_number,
        "has_pending_changes": pending_count > 0 or investigation_count > 0,
        "pending_count": pending_count,
        "investigation_count": investigation_count
    }


def merge_approved_change_into_baseline(
    db: Session,
    change: Change,
    user_username: str
) -> BaselineSnapshot:
    """
    Merge a single approved change into the baseline.

    Instead of promoting an entire snapshot, this:
    1. Gets the current baseline
    2. Applies ONLY the approved field change
    3. Creates a new baseline snapshot with the merged result

    Args:
        db: Database session
        change: The approved Change object
        user_username: Username of the approving user

    Returns:
        The new baseline snapshot
    """
    asset_id = change.asset_id

    # Get current baseline
    current_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == True
    ).first()

    if not current_baseline:
        # No baseline - this shouldn't happen in normal flow
        # Fall back to using the new snapshot if available
        if change.new_snapshot_id:
            new_snapshot = db.query(BaselineSnapshot).filter(
                BaselineSnapshot.id == change.new_snapshot_id
            ).first()
            if new_snapshot:
                new_snapshot.is_current_baseline = True
                new_snapshot.promoted_at = datetime.utcnow()
                new_snapshot.promoted_by = user_username
                return new_snapshot
        return None

    # Start with current baseline config
    merged_config = json.loads(current_baseline.config_json)

    # Apply the approved change
    field_path = change.field_path

    if change.new_value:
        new_val = json.loads(change.new_value)
        _set_nested_value(merged_config, field_path, new_val)
    elif change.items_added or change.items_removed:
        _apply_array_change(merged_config, field_path, change)

    # Update timestamp if present
    if "timestamp" in merged_config:
        # Get timestamp from new snapshot if available
        if change.new_snapshot_id:
            new_snap = db.query(BaselineSnapshot).filter(
                BaselineSnapshot.id == change.new_snapshot_id
            ).first()
            if new_snap:
                new_config = json.loads(new_snap.config_json)
                if "timestamp" in new_config:
                    merged_config["timestamp"] = new_config["timestamp"]

    # Mark old baseline as not current
    current_baseline.is_current_baseline = False

    # Accumulate field tickets from previous baseline
    existing_field_tickets = {}
    if current_baseline.field_tickets_json:
        existing_field_tickets = json.loads(current_baseline.field_tickets_json)

    # Add this change's ticket to field tickets
    if change.ticket_number:
        existing_field_tickets[field_path] = change.ticket_number

    # Create new merged baseline snapshot
    new_baseline = BaselineSnapshot(
        asset_id=asset_id,
        captured_at=datetime.utcnow(),
        capture_timestamp=datetime.utcnow(),
        config_json=json.dumps(merged_config),
        config_hash=BaselineSnapshot.compute_hash(merged_config),
        source="field_merge",
        triggered_by=user_username,
        is_current_baseline=True,
        promoted_at=datetime.utcnow(),
        promoted_by=user_username,
        ticket_number=current_baseline.ticket_number,  # Preserve original baseline ticket
        field_tickets_json=json.dumps(existing_field_tickets) if existing_field_tickets else None
    )
    db.add(new_baseline)

    return new_baseline


def get_baseline_with_pending_overlay(
    db: Session,
    asset_id: int
) -> Dict[str, Any]:
    """
    Get the current baseline with pending changes overlaid for review.

    This shows what the baseline WOULD look like if all pending changes
    were approved. Useful for preview during review.

    Returns:
        {
            "current_baseline": { ... },
            "preview_if_all_approved": { ... },
            "changes": [
                {
                    "field_path": "...",
                    "status": "pending|investigation",
                    "old_value": ...,
                    "new_value": ...
                }
            ]
        }
    """
    effective = compute_effective_baseline(db, asset_id, include_field_status=True)

    # Get pending/investigation changes
    pending_changes = db.query(Change).filter(
        Change.asset_id == asset_id,
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    ).all()

    # Create preview with all changes applied
    preview_config = copy.deepcopy(effective["config"]) if effective["config"] else {}

    changes_detail = []
    for change in pending_changes:
        change_info = {
            "id": change.id,
            "field_path": change.field_path,
            "change_type": change.change_type.value if change.change_type else None,
            "status": change.status.value,
            "old_value": json.loads(change.old_value) if change.old_value else None,
            "new_value": json.loads(change.new_value) if change.new_value else None,
            "items_added": json.loads(change.items_added) if change.items_added else None,
            "items_removed": json.loads(change.items_removed) if change.items_removed else None,
            "days_in_investigation": change.days_in_investigation
        }
        changes_detail.append(change_info)

        # Apply to preview
        if change.new_value:
            _set_nested_value(preview_config, change.field_path, json.loads(change.new_value))
        elif change.items_added or change.items_removed:
            _apply_array_change(preview_config, change.field_path, change)

    return {
        "current_baseline": effective["config"],
        "preview_if_all_approved": preview_config,
        "field_statuses": effective["field_statuses"],
        "field_tickets": effective["field_tickets"],
        "field_first_seen": effective["field_first_seen"],
        "pending_changes": changes_detail,
        "baseline_snapshot_id": effective["baseline_snapshot_id"],
        "baseline_promoted_at": effective["baseline_promoted_at"],
        "ticket_number": effective["ticket_number"]
    }


def _set_nested_value(config: dict, field_path: str, value: Any) -> None:
    """
    Set a value in a nested dict using dot notation path.

    Example: _set_nested_value(config, "network.dns.servers", ["8.8.8.8"])
    """
    parts = field_path.split(".")
    current = config

    for i, part in enumerate(parts[:-1]):
        # Handle array index notation like "items[0]"
        if "[" in part:
            key, idx = part.split("[")
            idx = int(idx.rstrip("]"))
            if key not in current:
                current[key] = []
            while len(current[key]) <= idx:
                current[key].append({})
            current = current[key][idx]
        else:
            if part not in current:
                current[part] = {}
            current = current[part]

    # Set the final value
    final_key = parts[-1]
    if "[" in final_key:
        key, idx = final_key.split("[")
        idx = int(idx.rstrip("]"))
        if key not in current:
            current[key] = []
        while len(current[key]) <= idx:
            current[key].append(None)
        current[key][idx] = value
    else:
        current[final_key] = value


def _get_nested_value(config: dict, field_path: str) -> Any:
    """
    Get a value from a nested dict using dot notation path.
    """
    parts = field_path.split(".")
    current = config

    try:
        for part in parts:
            if "[" in part:
                key, idx = part.split("[")
                idx = int(idx.rstrip("]"))
                current = current[key][idx]
            else:
                current = current[part]
        return current
    except (KeyError, IndexError, TypeError):
        return None


def _apply_array_change(config: dict, field_path: str, change: Change) -> None:
    """
    Apply array item additions and removals to a config.
    """
    current_array = _get_nested_value(config, field_path)

    if current_array is None:
        current_array = []

    if not isinstance(current_array, list):
        # Field isn't an array - use new_value if available
        if change.new_value:
            _set_nested_value(config, field_path, json.loads(change.new_value))
        return

    # Remove items
    if change.items_removed:
        removed = json.loads(change.items_removed)
        for item in removed:
            if item in current_array:
                current_array.remove(item)

    # Add items
    if change.items_added:
        added = json.loads(change.items_added)
        for item in added:
            if item not in current_array:
                current_array.append(item)

    _set_nested_value(config, field_path, current_array)


def revert_approved_change(
    db: Session,
    change: Change,
    user_username: str
) -> bool:
    """
    Revert an approved change back to pending status.

    This restores the previous baseline by:
    1. Finding the baseline snapshot that existed before the approval
    2. Marking it as current again
    3. Marking the current merged baseline as not current

    Args:
        db: Database session
        change: The approved Change object to revert
        user_username: Username of the reverting user

    Returns:
        True if successful, False otherwise
    """
    asset_id = change.asset_id

    # Get the current baseline (the one created by the approval)
    current_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == True
    ).first()

    if not current_baseline:
        return False

    # Find the previous baseline (most recent non-current one before current)
    previous_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == False,
        BaselineSnapshot.id < current_baseline.id
    ).order_by(BaselineSnapshot.id.desc()).first()

    if previous_baseline:
        # Restore previous baseline as current
        current_baseline.is_current_baseline = False
        previous_baseline.is_current_baseline = True

    # Revert to appropriate status based on whether this was an investigation change
    if change.investigation_started_at:
        # Was an investigation change - restore to INVESTIGATION status
        change.status = ChangeStatus.INVESTIGATION
        change.resolution_notes = f"Reverted to investigation by {user_username} at {datetime.utcnow().isoformat()}"
    else:
        # Normal pending change - restore to PENDING
        change.status = ChangeStatus.PENDING
        change.resolution_notes = f"Reverted by {user_username} at {datetime.utcnow().isoformat()}"

    change.status_changed_at = datetime.utcnow()
    change.status_changed_by = user_username

    return True
