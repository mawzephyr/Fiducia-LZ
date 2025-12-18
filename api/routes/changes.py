"""
Change management routes for CIP-010 Baseline Engine.

Handles the approval/rejection workflow for detected changes.
"""
from datetime import datetime, timedelta
from typing import Optional
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db, Asset, AssetState, BaselineSnapshot, Change, ChangeStatus, AuditLog, Report, ReportType, SystemSetting, Group
from config import settings
from api.schemas import ChangeResponse, ChangeWithAsset, ChangeReview, BulkChangeReview
from api.routes.auth import get_current_user, User

router = APIRouter()


def _send_syslog_event(action: str, message: str, asset_id: int = None, asset_name: str = None,
                       user_id: int = None, username: str = None, details: dict = None):
    """Send event to syslog if enabled."""
    try:
        from services.syslog import get_syslog_service
        syslog_svc = get_syslog_service()
        if syslog_svc and syslog_svc.is_event_enabled(action):
            syslog_svc.send_event(
                event_type=action,
                message=message,
                asset_id=asset_id,
                asset_name=asset_name,
                user_id=user_id,
                username=username,
                details=details
            )
    except Exception:
        pass  # Don't let syslog failures affect main operation


def user_can_view_all_groups(user: User) -> bool:
    """Check if user can view changes across all groups (admin or no group assigned)."""
    return user.role == "admin" or user.group_id is None


def _safe_json_loads(value):
    """Safely parse JSON, returning the raw value if parsing fails."""
    if value is None:
        return None
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        # Return raw value for non-JSON strings (e.g., asset names in rename changes)
        return value


@router.get("/pending", response_model=list[ChangeWithAsset])
async def get_pending_changes(
    group_id: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all pending changes for review.

    Optionally filter by group. Returns changes with asset info.
    Non-admin users can only see changes for their assigned group.
    """
    query = db.query(Change, Asset).join(Asset).filter(
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    )

    # Apply group filter based on user permissions
    if group_id:
        # Explicit group filter - verify user has access
        if not user_can_view_all_groups(current_user) and current_user.group_id != group_id:
            raise HTTPException(status_code=403, detail="You can only view changes for your assigned group")
        query = query.filter(Asset.group_id == group_id)
    elif not user_can_view_all_groups(current_user):
        # No explicit filter but user is restricted to their group
        query = query.filter(Asset.group_id == current_user.group_id)

    results = query.order_by(Change.detected_at.desc()).all()
    
    changes = []
    for change, asset in results:
        changes.append(ChangeWithAsset(
            id=change.id,
            asset_id=change.asset_id,
            asset_name=asset.asset_name,
            asset_group_id=asset.group_id,
            field_path=change.field_path,
            change_type=change.change_type,
            old_value=_safe_json_loads(change.old_value),
            new_value=_safe_json_loads(change.new_value),
            items_added=_safe_json_loads(change.items_added),
            items_removed=_safe_json_loads(change.items_removed),
            detected_at=change.detected_at,
            status=change.status.value,
            status_changed_at=change.status_changed_at,
            status_changed_by=change.status_changed_by,
            days_in_investigation=change.days_in_investigation or 0,
            change_signature=change.change_signature,
            resolution_notes=change.resolution_notes,
            ticket_number=change.ticket_number,
            compliance_due_date=change.compliance_due_date,
            resolved_at=change.resolved_at
        ))

    return changes


@router.get("/grouped")
async def get_grouped_changes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get pending changes grouped by signature.

    This enables bulk approval of identical changes across multiple assets.
    Non-admin users can only see changes for their assigned group.
    """
    # Get all pending changes with asset info
    query = db.query(Change, Asset).join(Asset).filter(
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    )

    # Filter by user's group if not admin
    if not user_can_view_all_groups(current_user):
        query = query.filter(Asset.group_id == current_user.group_id)

    results = query.all()
    
    # Group by signature
    grouped = {}
    asset_specific = {}

    for change, asset in results:
        # Use change ID as signature fallback for changes without signatures (e.g., rename requests)
        sig = change.change_signature or str(change.id)

        if sig not in grouped:
            grouped[sig] = {
                "signature": sig,
                "field_path": change.field_path,
                "change_type": change.change_type,
                "old_value": _safe_json_loads(change.old_value),
                "new_value": _safe_json_loads(change.new_value),
                "items_added": _safe_json_loads(change.items_added),
                "items_removed": _safe_json_loads(change.items_removed),
                "compliance_due_date": change.compliance_due_date.isoformat() if change.compliance_due_date else None,
                "assets": [],
                "change_ids": []
            }
        
        grouped[sig]["assets"].append({
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "group_id": asset.group_id,
            "asset_state": asset.current_state.value if asset.current_state else "active",
            "state_changed_at": asset.state_changed_at.isoformat() if asset.state_changed_at else None,
            "change_id": change.id,
            "change_status": change.status.value if change.status else "pending",
            "compliance_due_date": change.compliance_due_date.isoformat() if change.compliance_due_date else None,
            "ticket_number": change.ticket_number,
                    "items_added": _safe_json_loads(change.items_added) if change.items_added else None,
                    "items_removed": _safe_json_loads(change.items_removed) if change.items_removed else None
        })
        grouped[sig]["change_ids"].append(change.id)
    
    # Separate into grouped (multiple assets) and asset-specific (single asset)
    multi_asset = []
    single_asset = []
    
    for sig, data in grouped.items():
        if len(data["assets"]) > 1:
            multi_asset.append(data)
        else:
            single_asset.append(data)
    
    return {
        "grouped_changes": multi_asset,
        "asset_specific_changes": single_asset
    }


@router.put("/{change_id}/review", response_model=ChangeResponse)
async def review_change(
    change_id: int,
    review: ChangeReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approve, reject, or mark for investigation a single change.
    """
    change = db.query(Change).filter(Change.id == change_id).first()
    if not change:
        raise HTTPException(status_code=404, detail="Change not found")

    # Require ticket number for all change reviews
    if not review.ticket_number or not review.ticket_number.strip():
        raise HTTPException(status_code=400, detail="Ticket number is required for all change reviews")

    old_status = change.status
    new_status = ChangeStatus(review.status)
    
    change.status = new_status
    change.status_changed_at = datetime.utcnow()
    change.status_changed_by = current_user.username

    if review.resolution_notes:
        change.resolution_notes = review.resolution_notes

    if review.ticket_number:
        change.ticket_number = review.ticket_number

    # Track investigation start (v4.0.0: timer is per-change, already set on detection)
    if new_status == ChangeStatus.INVESTIGATION and old_status != ChangeStatus.INVESTIGATION:
        change.investigation_started_at = datetime.utcnow()

    # Set resolved_at when approved or rejected (v4.0.0: preserve for audit)
    if new_status in [ChangeStatus.APPROVED, ChangeStatus.REJECTED]:
        change.resolved_at = datetime.utcnow()

    # If approved, promote the new baseline
    if new_status == ChangeStatus.APPROVED:
        _promote_change(db, change, current_user)
    
    # Generate report first to get the ID
    report_id = _generate_change_report(db, change, review.status, current_user)

    # Get asset info for audit log
    asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
    
    # Audit log with report link
    audit = AuditLog(
        user_id=current_user.id,
        action=f"change_{review.status}",
        action_detail=f"{asset.asset_name if asset else 'Unknown'}: {change.field_path} - {review.status}" + (f" (Ticket: {review.ticket_number})" if review.ticket_number else ""),
        asset_id=change.asset_id,
        change_id=change.id,
        report_id=report_id,
        asset_name=asset.asset_name if asset else None,
        details_json=json.dumps({
            "field": change.field_path,
            "ticket_number": review.ticket_number,
            "old_status": old_status.value,
            "new_status": new_status.value,
            "resolution_notes": review.resolution_notes
        })
    )
    db.add(audit)
    _send_syslog_event(f"change_{review.status}", f"Changed status from {old_status.value} to {new_status.value}",
                       asset_id=change.asset_id, asset_name=asset.asset_name if asset else None,
                       user_id=current_user.id, username=current_user.username,
                       details={"field": change.field_path, "ticket_number": review.ticket_number})

    db.commit()

    # Get the audit log ID after commit (for PDF generation)
    audit_log_id = audit.id if audit else None
    db.refresh(change)

    return change


@router.post("/bulk-review")
async def bulk_review_by_signature(
    review: BulkChangeReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Approve or reject all changes with the same signature.
    
    This is the bulk approval feature for identical changes across assets.
    """
    # Find all changes with this signature
    changes = db.query(Change).filter(
        Change.change_signature == review.signature,
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    ).all()

    # Fallback: if signature looks like an ID (numeric) and no changes found, try by ID
    if not changes and review.signature.isdigit():
        change = db.query(Change).filter(
            Change.id == int(review.signature),
            Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
        ).first()
        if change:
            changes = [change]

    if not changes:
        raise HTTPException(status_code=404, detail="No pending changes found with this signature")

    # Require ticket number for all change reviews
    if not review.ticket_number or not review.ticket_number.strip():
        raise HTTPException(status_code=400, detail="Ticket number is required for all change reviews")

    new_status = ChangeStatus(review.status)
    affected_assets = []
    
    for change in changes:
        old_status = change.status
        change.status = new_status
        change.status_changed_at = datetime.utcnow()
        change.status_changed_by = current_user.username

        if review.resolution_notes:
            change.resolution_notes = review.resolution_notes

        if review.ticket_number:
            change.ticket_number = review.ticket_number

        if new_status == ChangeStatus.INVESTIGATION and old_status != ChangeStatus.INVESTIGATION:
            change.investigation_started_at = datetime.utcnow()

        # Set resolved_at when approved or rejected (v4.0.0: preserve for audit)
        if new_status in [ChangeStatus.APPROVED, ChangeStatus.REJECTED]:
            change.resolved_at = datetime.utcnow()

        if new_status == ChangeStatus.APPROVED:
            _promote_change(db, change, current_user)

        # Track affected asset
        asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
        if asset:
            affected_assets.append({"id": asset.id, "name": asset.asset_name})
    
    # Generate bulk report first to get the ID
    report_id = _generate_bulk_report(db, changes, review.status, current_user, affected_assets)

    # Audit log with report link
    audit = AuditLog(
        user_id=current_user.id,
        action=f"bulk_{review.status}",
        action_detail=f"Bulk {review.status} of {len(changes)} changes" + (f" (Ticket: {review.ticket_number})" if review.ticket_number else ""),
        details_json=json.dumps({
            "affected_assets": affected_assets,
            "signature": review.signature,
            "ticket_number": review.ticket_number,
            "resolution_notes": review.resolution_notes
        }),
        report_id=report_id
    )
    db.add(audit)

    db.commit()

    # Get the audit log ID after commit (for PDF generation)
    audit_log_id = audit.id if audit else None
    
    return {
        "message": f"{len(changes)} changes {review.status}",
        "affected_assets": affected_assets
    }


class FinalizeRequest(BaseModel):
    """Request body for finalize endpoint."""
    investigation_notes: Optional[dict] = None  # Dict of asset_id -> notes


@router.post("/finalize")
async def finalize_all_approved(
    request: FinalizeRequest = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Finalize all approved changes.

    For each asset where ALL changes are approved, mark changes as FINALIZED
    and update the asset state to COMPLIANT.

    Returns a detailed promotion summary with all change values for ticket documentation.

    Optional: investigation_notes dict maps asset_id to investigation notes for the report.
    """
    print("[DEBUG] Starting finalize_all_approved")

    # Extract investigation notes if provided
    investigation_notes = {}
    if request and request.investigation_notes:
        # Convert string keys to int (asset IDs come as strings from JSON)
        investigation_notes = {int(k): v for k, v in request.investigation_notes.items()}

    # Get all approved changes grouped by asset
    approved_changes = db.query(Change).filter(
        Change.status == ChangeStatus.APPROVED
    ).all()

    print(f"[DEBUG] Found {len(approved_changes)} approved changes")

    # Group by asset
    by_asset = {}
    for change in approved_changes:
        if change.asset_id not in by_asset:
            by_asset[change.asset_id] = []
        by_asset[change.asset_id].append(change)

    finalized_assets = []

    for asset_id, changes in by_asset.items():
        print(f"[DEBUG] Processing asset {asset_id} with {len(changes)} approved changes")

        # Finalize approved changes immediately - don't wait for all changes to be reviewed
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            # Track investigation state BEFORE processing
            # Check if asset is in investigation OR if any changes were marked as investigation
            was_in_investigation = asset.current_state == AssetState.INVESTIGATION or any(c.investigation_started_at for c in changes)
            # Get investigation start time from asset or earliest change
            if was_in_investigation:
                change_start_times = [c.investigation_started_at for c in changes if c.investigation_started_at]
                investigation_started_at = min(change_start_times) if change_start_times else asset.state_changed_at
            else:
                investigation_started_at = None

            # Capture change details BEFORE deleting for the promotion summary
            change_details = []
            for change in changes:
                # Parse JSON values for display
                old_val = change.old_value
                new_val = change.new_value
                try:
                    if old_val:
                        old_val = json.loads(old_val)
                except:
                    pass
                try:
                    if new_val:
                        new_val = json.loads(new_val)
                except:
                    pass

                # Calculate time to close (days from detection to finalization)
                time_to_close_days = None
                if change.detected_at:
                    time_to_close_days = (datetime.utcnow() - change.detected_at).days

                change_details.append({
                    "field": change.field_path,
                    "change_type": change.change_type.value if hasattr(change.change_type, 'value') else str(change.change_type),
                    "old_value": old_val,
                    "new_value": new_val,
                    "approved_by": change.status_changed_by,
                    "approved_at": change.status_changed_at.isoformat() if change.status_changed_at else None,
                    "resolution_notes": change.resolution_notes,
                    "ticket_number": change.ticket_number,
                    "items_added": _safe_json_loads(change.items_added) if change.items_added else None,
                    "items_removed": _safe_json_loads(change.items_removed) if change.items_removed else None,
                    "detected_at": change.detected_at.isoformat() if change.detected_at else None,
                    "time_to_close_days": time_to_close_days
                })

                # Delete the finalized changes from pending queue
                db.delete(change)

            # Check if there are remaining pending changes for this asset
            remaining_pending = db.query(Change).filter(
                Change.asset_id == asset_id,
                Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
            ).count()

            # Only set to COMPLIANT if all changes are now reviewed
            if remaining_pending == 0:
                asset.current_state = AssetState.COMPLIANT
                asset.state_changed_at = datetime.utcnow()

            asset.last_approved_change = datetime.utcnow()

            # Get group name for the summary
            group_name = None
            if asset.group_id:
                group = db.query(Group).filter(Group.id == asset.group_id).first()
                if group:
                    group_name = group.name

            # Calculate investigation closure info
            investigation_closed = was_in_investigation and remaining_pending == 0
            investigation_duration_days = None
            if investigation_closed and investigation_started_at:
                investigation_duration_days = (datetime.utcnow() - investigation_started_at).days

            finalized_assets.append({
                "id": asset.id,
                "name": asset.asset_name,
                "fqdn": asset.fqdn,
                "group": group_name,
                "changes_finalized": len(changes),
                "remaining_pending": remaining_pending,
                "changes": change_details,
                "was_investigation": was_in_investigation,
                "investigation_closed": investigation_closed,
                "investigation_started_at": investigation_started_at.isoformat() if investigation_started_at else None,
                "investigation_duration_days": investigation_duration_days,
                "investigation_notes": investigation_notes.get(asset.id, "")
            })
            print(f"[DEBUG] Finalized {len(changes)} changes for {asset.asset_name}, {remaining_pending} pending remain" +
                  (f", INVESTIGATION CLOSED after {investigation_duration_days} days" if investigation_closed else ""))

    # Generate promotion summary report
    promotion_summary = _generate_promotion_summary(finalized_assets, current_user.username)

    # Audit log with full details
    audit = None
    if finalized_assets:
        total_changes = sum(a['changes_finalized'] for a in finalized_assets)
        investigation_closures = [a for a in finalized_assets if a.get('investigation_closed')]

        if investigation_closures:
            action_detail = (f"Closed {len(investigation_closures)} investigation(s) - asset(s) restored to compliance. "
                            f"Finalized {len(finalized_assets)} assets with {total_changes} total changes.")
        else:
            action_detail = f"Finalized {len(finalized_assets)} assets with {total_changes} total changes."

        audit = AuditLog(
            user_id=current_user.id,
            action="finalize_baselines",
            action_detail=action_detail,
            details_json=json.dumps({
                "finalized_assets": finalized_assets,
                "investigations_closed": investigation_closures
            })
        )
        db.add(audit)

        # Send syslog event
        _send_syslog_event(
            action="finalize_baselines",
            message=action_detail,
            user_id=current_user.id,
            username=current_user.username,
            details={
                "finalized_count": len(finalized_assets),
                "total_changes": total_changes,
                "investigations_closed": len(investigation_closures)
            }
        )

    db.commit()

    # Get the audit log ID after commit (for PDF generation)
    audit_log_id = audit.id if audit else None

    print(f"[DEBUG] Finalize complete: {len(finalized_assets)} assets")

    return {
        "message": f"Finalized {len(finalized_assets)} assets",
        "finalized_assets": finalized_assets,
        "promotion_summary": promotion_summary,
        "audit_log_id": audit_log_id
    }


def _generate_promotion_summary(finalized_assets: list, username: str) -> str:
    """Generate a detailed text summary of all promoted changes for ticket documentation."""
    from datetime import datetime
    from config import settings

    # Check if this is primarily an investigation closure
    investigation_closures = [a for a in finalized_assets if a.get('investigation_closed')]

    # If we have investigation closures, generate a comprehensive investigation closure report
    if investigation_closures:
        return _generate_investigation_closure_report(finalized_assets, investigation_closures, username)

    # Standard promotion summary for non-investigation closures
    lines = [
        "=" * 70,
        "BASELINE PROMOTION SUMMARY",
        f"Fiducia v{settings.APP_VERSION}",
        "=" * 70,
        f"Generated:     {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Promoted By:   {username}",
        f"Assets:        {len(finalized_assets)}",
        f"Total Changes: {sum(a['changes_finalized'] for a in finalized_assets)}",
        "=" * 70,
    ]

    for asset in finalized_assets:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"ASSET: {asset['name']}")
        if asset.get('fqdn'):
            lines.append(f"FQDN:  {asset['fqdn']}")
        if asset.get('group'):
            lines.append(f"Group: {asset['group']}")
        lines.append(f"Changes Approved: {asset['changes_finalized']}")
        lines.append("-" * 70)

        for change in asset.get('changes', []):
            lines.append("")
            lines.append(f"  Field: {change['field']}")
            lines.append(f"  Type:  {change['change_type']}")

            old_val = change.get('old_value')
            new_val = change.get('new_value')

            # Format values for display
            if isinstance(old_val, list):
                old_val = ", ".join(str(v) for v in old_val)
            if isinstance(new_val, list):
                new_val = ", ".join(str(v) for v in new_val)

            if old_val is not None:
                lines.append(f"  Old:   {old_val}")
            if new_val is not None:
                lines.append(f"  New:   {new_val}")

            if change.get('ticket_number'):
                lines.append(f"  Ticket #: {change['ticket_number']}")
            if change.get('approved_by'):
                lines.append(f"  Approved By: {change['approved_by']} at {change.get('approved_at', 'N/A')}")
            if change.get('detected_at'):
                lines.append(f"  Detected:    {change['detected_at']}")
            if change.get('time_to_close_days') is not None:
                lines.append(f"  Time to Close: {change['time_to_close_days']} days")
            if change.get('resolution_notes'):
                lines.append(f"  Notes: {change['resolution_notes']}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF PROMOTION SUMMARY")
    lines.append("=" * 70)

    return "\n".join(lines)


def _generate_investigation_closure_report(finalized_assets: list, investigation_closures: list, username: str) -> str:
    """
    Generate a comprehensive investigation closure report.

    This report mirrors the investigation opening format and includes ALL details:
    - Full investigation timeline
    - All ticket numbers
    - Investigation notes
    - Complete before/after values for each change
    - Resolution details
    """
    from datetime import datetime
    from config import settings

    closure_time = datetime.utcnow()
    total_changes = sum(a['changes_finalized'] for a in investigation_closures)

    # Collect all unique ticket numbers
    all_tickets = set()
    for asset in investigation_closures:
        for change in asset.get('changes', []):
            if change.get('ticket_number'):
                all_tickets.add(change['ticket_number'])

    lines = [
        "╔" + "═" * 68 + "╗",
        "║" + "INVESTIGATION CLOSURE SUMMARY".center(68) + "║",
        "║" + f"Fiducia v{settings.APP_VERSION}".center(68) + "║",
        "╚" + "═" * 68 + "╝",
        "",
        "=" * 70,
        "CLOSURE OVERVIEW",
        "=" * 70,
        "",
        f"  Report Generated:      {closure_time.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"  Closed By:             {username}",
        f"  Investigations Closed: {len(investigation_closures)}",
        f"  Total Changes Resolved: {total_changes}",
        "",
    ]

    if all_tickets:
        lines.append(f"  Related Ticket Numbers:")
        for ticket in sorted(all_tickets):
            lines.append(f"    • {ticket}")
        lines.append("")

    # Also include any non-investigation assets that were finalized
    non_investigation_assets = [a for a in finalized_assets if not a.get('investigation_closed')]
    if non_investigation_assets:
        lines.append(f"  Additional Assets Finalized: {len(non_investigation_assets)}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("")

    # Detailed report for each investigation closure
    for idx, asset in enumerate(investigation_closures, 1):
        lines.append("╔" + "═" * 68 + "╗")
        lines.append("║" + f" INVESTIGATION #{idx}: {asset['name']} ".center(68) + "║")
        lines.append("╚" + "═" * 68 + "╝")
        lines.append("")

        # Asset Information Section
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " ASSET INFORMATION ".center(68) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        lines.append(f"  Asset Name:    {asset['name']}")
        if asset.get('fqdn'):
            lines.append(f"  FQDN:          {asset['fqdn']}")
        if asset.get('group'):
            lines.append(f"  Team/Group:    {asset['group']}")
        lines.append(f"  Asset ID:      {asset.get('id', 'N/A')}")
        lines.append("")

        # Investigation Timeline Section
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " INVESTIGATION TIMELINE ".center(68) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")

        if asset.get('investigation_started_at'):
            # Parse the ISO format date
            try:
                start_dt = datetime.fromisoformat(asset['investigation_started_at'].replace('Z', '+00:00'))
                lines.append(f"  Investigation Opened:   {start_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            except:
                lines.append(f"  Investigation Opened:   {asset['investigation_started_at']}")
        else:
            lines.append(f"  Investigation Opened:   (date not recorded)")

        lines.append(f"  Investigation Closed:   {closure_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")

        if asset.get('investigation_duration_days') is not None:
            duration = asset['investigation_duration_days']
            if duration == 0:
                lines.append(f"  Duration:               Same day resolution")
            elif duration == 1:
                lines.append(f"  Duration:               1 day")
            else:
                lines.append(f"  Duration:               {duration} days")

            # Add compliance status based on 35-day window
            if duration <= 35:
                lines.append(f"  Compliance Status:      ✅ WITHIN 35-DAY WINDOW")
            else:
                lines.append(f"  Compliance Status:      ⚠️  EXCEEDED 35-DAY WINDOW (by {duration - 35} days)")

        lines.append(f"  Changes Resolved:       {asset['changes_finalized']}")
        lines.append("")

        # Investigation Notes Section (if provided)
        if asset.get('investigation_notes'):
            lines.append("┌" + "─" * 68 + "┐")
            lines.append("│" + " INVESTIGATION NOTES ".center(68) + "│")
            lines.append("└" + "─" * 68 + "┘")
            lines.append("")
            for note_line in asset['investigation_notes'].split('\n'):
                # Word wrap long lines
                if len(note_line) > 66:
                    words = note_line.split()
                    current_line = "  "
                    for word in words:
                        if len(current_line) + len(word) + 1 <= 68:
                            current_line += word + " "
                        else:
                            lines.append(current_line.rstrip())
                            current_line = "  " + word + " "
                    if current_line.strip():
                        lines.append(current_line.rstrip())
                else:
                    lines.append(f"  {note_line}")
            lines.append("")

        # Changes Resolved Section - FULL DETAILS
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " CHANGES RESOLVED (FULL DETAILS) ".center(68) + "│")
        lines.append("└" + "─" * 68 + "┘")

        for change_idx, change in enumerate(asset.get('changes', []), 1):
            lines.append("")
            lines.append(f"  ── Change {change_idx} of {len(asset.get('changes', []))} " + "─" * 40)
            lines.append("")
            lines.append(f"  Field Path:      {change['field']}")
            lines.append(f"  Change Type:     {change['change_type'].upper().replace('_', ' ')}")

            if change.get('ticket_number'):
                lines.append(f"  Ticket #:        {change['ticket_number']}")

            lines.append("")

            # Check for array_modified type
            change_type = change.get('change_type', '').lower()
            if change_type == 'array_modified':
                items_added = change.get('items_added') or []
                items_removed = change.get('items_removed') or []
                if items_added:
                    lines.append(f'  + ADDED ({len(items_added)} items):')
                    for item in items_added:
                        if isinstance(item, dict):
                            item_str = ', '.join(f"{k}: {v}" for k, v in item.items())
                            lines.append(f'    + {{ {item_str} }}')
                        else:
                            lines.append(f'    + {item}')
                    lines.append('')
                if items_removed:
                    lines.append(f'  - REMOVED ({len(items_removed)} items):')
                    for item in items_removed:
                        if isinstance(item, dict):
                            item_str = ', '.join(f"{k}: {v}" for k, v in item.items())
                            lines.append(f'    - {{ {item_str} }}')
                        else:
                            lines.append(f'    - {item}')
                    lines.append('')
            else:
                old_val = change.get('old_value')
                new_val = change.get('new_value')
                lines.append('  Old: ' + str(old_val if old_val else '(none)'))
                lines.append('  New: ' + str(new_val if new_val else '(none)'))
                lines.append('')

            # Resolution details
            lines.append("  Resolution:")
            lines.append("  " + "·" * 40)
            if change.get('approved_by'):
                lines.append(f"    Reviewed By:   {change['approved_by']}")
            if change.get('approved_at'):
                try:
                    approved_dt = datetime.fromisoformat(change['approved_at'].replace('Z', '+00:00'))
                    lines.append(f"    Reviewed At:   {approved_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC")
                except:
                    lines.append(f"    Reviewed At:   {change['approved_at']}")

            if change.get('resolution_notes'):
                lines.append(f"    Notes:         {change['resolution_notes']}")

            lines.append(f"    Final Status:  ✅ APPROVED → PROMOTED TO BASELINE")
            lines.append("")

        # Resolution Summary for this asset
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " RESOLUTION SUMMARY ".center(68) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        lines.append("  ✓ Investigation has been completed and closed.")
        lines.append("  ✓ All configuration changes have been reviewed and approved.")
        lines.append("  ✓ Approved changes have been promoted to the official baseline.")
        lines.append("  ✓ Asset has been restored to COMPLIANT status.")
        lines.append("  ✓ CIP-010 compliance requirements have been satisfied.")
        lines.append("")
        lines.append("=" * 70)
        lines.append("")

    # Include non-investigation finalized assets if any
    if non_investigation_assets:
        lines.append("┌" + "─" * 68 + "┐")
        lines.append("│" + " ADDITIONAL BASELINE PROMOTIONS ".center(68) + "│")
        lines.append("└" + "─" * 68 + "┘")
        lines.append("")
        lines.append("  The following assets were also finalized (not from investigation):")
        lines.append("")

        for asset in non_investigation_assets:
            lines.append(f"  • {asset['name']}: {asset['changes_finalized']} change(s) promoted")
        lines.append("")

    # Final footer
    lines.append("╔" + "═" * 68 + "╗")
    lines.append("║" + " END OF INVESTIGATION CLOSURE SUMMARY ".center(68) + "║")
    lines.append("╚" + "═" * 68 + "╝")

    return "\n".join(lines)


@router.get("/ticket-search/{ticket_number}")
async def search_by_ticket(
    ticket_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Search for all changes associated with a ticket number across all assets.

    Returns all approved, rejected, and pending changes that have the specified
    ticket number, grouped by asset.
    """
    # Search audit logs for finalized changes with this ticket
    audit_logs = db.query(AuditLog).filter(
        AuditLog.action == "finalize_baselines"
    ).order_by(AuditLog.timestamp.desc()).all()

    results_by_asset = {}

    for log in audit_logs:
        if not log.details_json:
            continue
        try:
            details = json.loads(log.details_json)
            for asset_data in details.get("finalized_assets", []):
                for change in asset_data.get("changes", []):
                    if change.get("ticket_number") == ticket_number:
                        asset_id = asset_data.get("id")
                        asset_name = asset_data.get("name")

                        if asset_name not in results_by_asset:
                            results_by_asset[asset_name] = {
                                "asset_id": asset_id,
                                "asset_name": asset_name,
                                "asset_fqdn": asset_data.get("fqdn"),
                                "group": asset_data.get("group"),
                                "changes": []
                            }

                        results_by_asset[asset_name]["changes"].append({
                            "field": change.get("field"),
                            "change_type": change.get("change_type"),
                            "old_value": change.get("old_value"),
                            "new_value": change.get("new_value"),
                            "status": "approved",  # Finalized = approved
                            "approved_by": change.get("approved_by"),
                            "approved_at": change.get("approved_at"),
                            "finalized_at": log.timestamp.isoformat(),
                            "resolution_notes": change.get("resolution_notes")
                        })
        except json.JSONDecodeError:
            continue

    # Also search current pending/investigation changes
    pending_changes = db.query(Change).filter(
        Change.ticket_number == ticket_number
    ).all()

    for change in pending_changes:
        asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
        if not asset:
            continue

        asset_name = asset.asset_name
        if asset_name not in results_by_asset:
            group = db.query(Group).filter(Group.id == asset.group_id).first()
            results_by_asset[asset_name] = {
                "asset_id": asset.id,
                "asset_name": asset_name,
                "asset_fqdn": asset.fqdn,
                "group": group.name if group else "Unassigned",
                "changes": []
            }

        results_by_asset[asset_name]["changes"].append({
            "field": change.field_path,
            "change_type": change.change_type.value if change.change_type else None,
            "old_value": _safe_json_loads(change.old_value),
            "new_value": _safe_json_loads(change.new_value),
            "status": change.status.value,
            "approved_by": change.status_changed_by,
            "approved_at": change.status_changed_at.isoformat() if change.status_changed_at else None,
            "finalized_at": None,
            "resolution_notes": change.resolution_notes
        })

    # Convert to list and sort by asset name
    results = list(results_by_asset.values())
    results.sort(key=lambda x: x["asset_name"])

    # Calculate totals
    total_changes = sum(len(r["changes"]) for r in results)
    approved_count = sum(1 for r in results for c in r["changes"] if c["status"] == "approved")
    rejected_count = sum(1 for r in results for c in r["changes"] if c["status"] == "rejected")
    pending_count = sum(1 for r in results for c in r["changes"] if c["status"] in ["pending", "investigation"])

    return {
        "ticket_number": ticket_number,
        "total_assets": len(results),
        "total_changes": total_changes,
        "approved_count": approved_count,
        "rejected_count": rejected_count,
        "pending_count": pending_count,
        "assets": results
    }


@router.get("/approved")
async def get_approved_changes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all approved changes that can be reverted.

    Only changes approved within the last 24 hours can be reverted.
    """
    # Get the revert window from settings (default 24 hours)
    revert_window_hours = 24
    revert_window_setting = db.query(SystemSetting).filter(
        SystemSetting.key == "revert_window_hours"
    ).first()
    if revert_window_setting and revert_window_setting.value:
        try:
            revert_window_hours = int(revert_window_setting.value)
        except ValueError:
            pass

    cutoff = datetime.utcnow() - timedelta(hours=revert_window_hours)

    query = db.query(Change, Asset).join(Asset).filter(
        Change.status == ChangeStatus.APPROVED,
        Change.status_changed_at >= cutoff
    )

    # Filter by user's group if not admin
    if not user_can_view_all_groups(current_user):
        query = query.filter(Asset.group_id == current_user.group_id)

    results = query.order_by(Change.status_changed_at.desc()).all()

    approved = []
    for change, asset in results:
        approved.append({
            "id": change.id,
            "asset_id": change.asset_id,
            "asset_name": asset.asset_name,
            "field_path": change.field_path,
            "change_type": change.change_type,
            "old_value": _safe_json_loads(change.old_value),
            "new_value": _safe_json_loads(change.new_value),
            "status": change.status.value,
            "status_changed_at": change.status_changed_at.isoformat() if change.status_changed_at else None,
            "status_changed_by": change.status_changed_by,
            "ticket_number": change.ticket_number,
                    "items_added": _safe_json_loads(change.items_added) if change.items_added else None,
                    "items_removed": _safe_json_loads(change.items_removed) if change.items_removed else None,
            "can_revert": True,  # Within the window
            "revert_window_hours": revert_window_hours
        })

    return {
        "approved_changes": approved,
        "revert_window_hours": revert_window_hours,
        "total": len(approved)
    }


@router.put("/{change_id}/revert")
async def revert_change(
    change_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Revert an approved change back to pending status.

    Only changes approved within the revert window can be reverted.
    This restores the previous baseline and sets the change back to PENDING.
    """
    from services.baseline import revert_approved_change

    change = db.query(Change).filter(Change.id == change_id).first()
    if not change:
        raise HTTPException(status_code=404, detail="Change not found")

    if change.status != ChangeStatus.APPROVED:
        raise HTTPException(status_code=400, detail="Can only revert approved changes")

    # Check revert window
    revert_window_hours = 24
    revert_window_setting = db.query(SystemSetting).filter(
        SystemSetting.key == "revert_window_hours"
    ).first()
    if revert_window_setting and revert_window_setting.value:
        try:
            revert_window_hours = int(revert_window_setting.value)
        except ValueError:
            pass

    cutoff = datetime.utcnow() - timedelta(hours=revert_window_hours)
    if change.status_changed_at and change.status_changed_at < cutoff:
        raise HTTPException(
            status_code=400,
            detail=f"Change was approved more than {revert_window_hours} hours ago and cannot be reverted"
        )

    # Perform the revert
    success = revert_approved_change(db, change, current_user.username)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to revert change")

    # Get asset info for response
    asset = db.query(Asset).filter(Asset.id == change.asset_id).first()

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="revert_approval",
        action_detail=f"{asset.asset_name if asset else 'Unknown'}: Reverted approval for {change.field_path}",
        asset_id=change.asset_id,
        change_id=change.id,
        asset_name=asset.asset_name if asset else None,
        details_json=json.dumps({
            "field": change.field_path,
            "ticket_number": change.ticket_number
        })
    )
    db.add(audit)

    # Send syslog event
    _send_syslog_event(
        action="revert_approval",
        message=f"Reverted approval for {change.field_path}",
        asset_id=change.asset_id,
        asset_name=asset.asset_name if asset else None,
        user_id=current_user.id,
        username=current_user.username,
        details={"change_id": change.id, "field_path": change.field_path}
    )

    db.commit()

    # Get the audit log ID after commit (for PDF generation)
    audit_log_id = audit.id if audit else None

    return {
        "message": f"Successfully reverted approval for {change.field_path}",
        "change_id": change.id,
        "asset_name": asset.asset_name if asset else "Unknown",
        "new_status": "pending"
    }


@router.post("/revert-all")
async def revert_all_approved(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Revert all approved changes within the revert window back to pending.
    """
    from services.baseline import revert_approved_change

    # Check revert window
    revert_window_hours = 24
    revert_window_setting = db.query(SystemSetting).filter(
        SystemSetting.key == "revert_window_hours"
    ).first()
    if revert_window_setting and revert_window_setting.value:
        try:
            revert_window_hours = int(revert_window_setting.value)
        except ValueError:
            pass

    cutoff = datetime.utcnow() - timedelta(hours=revert_window_hours)

    query = db.query(Change).filter(
        Change.status == ChangeStatus.APPROVED,
        Change.status_changed_at >= cutoff
    )

    # Filter by user's group if not admin
    if not user_can_view_all_groups(current_user):
        query = query.join(Asset).filter(Asset.group_id == current_user.group_id)

    approved_changes = query.all()

    if not approved_changes:
        return {"message": "No approved changes to revert", "reverted": 0}

    reverted = 0
    for change in approved_changes:
        if revert_approved_change(db, change, current_user.username):
            reverted += 1

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="bulk_revert",
        action_detail=f"Reverted {reverted} approved changes",
        details_json=json.dumps({"change_ids": [c.id for c in approved_changes]})
    )
    db.add(audit)

    # Send syslog event
    _send_syslog_event(
        action="bulk_revert",
        message=f"Reverted {reverted} approved changes",
        user_id=current_user.id,
        username=current_user.username,
        details={"reverted_count": reverted, "change_ids": [c.id for c in approved_changes]}
    )

    db.commit()

    # Get the audit log ID after commit (for PDF generation)
    audit_log_id = audit.id if audit else None

    return {
        "message": f"Reverted {reverted} approved changes",
        "reverted": reverted
    }


def _promote_change(db: Session, change: Change, user: User):
    """
    Promote a change by merging it into the current baseline.

    This uses field-level merge instead of wholesale snapshot promotion.
    Only the approved field is updated in the baseline - rejected and
    investigation fields remain at their baseline values.

    Special case: "__asset_name__" field changes perform an asset rename
    instead of baseline merge.
    """
    from services.baseline import merge_approved_change_into_baseline

    print(f"[DEBUG] Promoting change {change.id} for asset {change.asset_id}")
    print(f"[DEBUG] Field: {change.field_path}, new_snapshot_id: {change.new_snapshot_id}")

    # Special handling for asset name changes (rename requests)
    if change.field_path == "__asset_name__":
        print(f"[DEBUG] Processing asset rename: {change.old_value} -> {change.new_value}")
        asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
        if not asset:
            print(f"[DEBUG] Asset not found for rename")
            return False

        old_name = asset.asset_name
        new_name = change.new_value

        # Perform the actual rename
        asset.asset_name = new_name
        asset.fqdn = new_name
        asset.last_approved_change = datetime.utcnow()

        # Update asset state - check if all changes are resolved
        remaining_changes = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.id != change.id,
            Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
        ).count()

        if remaining_changes == 0:
            asset.current_state = AssetState.COMPLIANT
            asset.state_changed_at = datetime.utcnow()
            # v4.0.0: compliance_due_date is now per-change, preserved for audit
            print(f"[DEBUG] Asset renamed and set to COMPLIANT")
        else:
            print(f"[DEBUG] Asset renamed but still has {remaining_changes} pending changes")

        print(f"[DEBUG] Asset renamed from '{old_name}' to '{new_name}'")
        return True

    # Use field-level merge for normal baseline changes
    new_baseline = merge_approved_change_into_baseline(db, change, user.username)

    if not new_baseline:
        print(f"[DEBUG] Field merge failed - no baseline to merge into")
        return False

    print(f"[DEBUG] Created merged baseline snapshot {new_baseline.id}")

    # Update asset state - check if all changes are resolved
    asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
    if asset:
        # Check for remaining pending/investigation changes
        remaining_changes = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.id != change.id,  # Exclude current change being approved
            Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
        ).count()

        if remaining_changes == 0:
            # All changes resolved - asset is now compliant
            asset.current_state = AssetState.COMPLIANT
            asset.last_approved_change = datetime.utcnow()
            asset.state_changed_at = datetime.utcnow()
            # v4.0.0: compliance_due_date is now per-change, preserved for audit
            print(f"[DEBUG] Updated asset {asset.asset_name} to COMPLIANT")
        else:
            asset.last_approved_change = datetime.utcnow()
            print(f"[DEBUG] Asset {asset.asset_name} still has {remaining_changes} pending changes")

    print(f"[DEBUG] Field-level promotion complete for change {change.id}")
    return True


def _generate_change_report(db: Session, change: Change, status: str, user: User) -> int:
    """Generate a report for a single change review. Returns the report ID."""
    asset = db.query(Asset).filter(Asset.id == change.asset_id).first()

    report_type = ReportType.APPROVAL if status == "approved" else (
        ReportType.REJECTION if status == "rejected" else ReportType.INVESTIGATION
    )

    content = _format_change_report(change, asset, status, user)

    report = Report(
        report_type=report_type,
        title=f"{status.upper()} Report - {asset.asset_name if asset else 'Unknown'} - {change.field_path}",
        report_content=content,
        generated_by=user.username,
        related_assets=json.dumps([change.asset_id]),
        related_changes=json.dumps([change.id])
    )
    db.add(report)
    db.flush()  # Get the report ID
    return report.id


def _generate_bulk_report(db: Session, changes: list, status: str, user: User, affected_assets: list) -> int:
    """Generate a report for bulk change review. Returns the report ID."""
    report_type = ReportType.APPROVAL if status == "approved" else (
        ReportType.REJECTION if status == "rejected" else ReportType.INVESTIGATION
    )

    content = _format_bulk_report(changes, status, user, affected_assets)

    report = Report(
        report_type=report_type,
        title=f"Bulk {status.upper()} Report - {len(changes)} changes across {len(affected_assets)} assets",
        report_content=content,
        generated_by=user.username,
        related_assets=json.dumps([a["id"] for a in affected_assets]),
        related_changes=json.dumps([c.id for c in changes])
    )
    db.add(report)
    db.flush()  # Get the report ID
    return report.id


def _format_change_report(change: Change, asset: Asset, status: str, user: User) -> str:
    """Format a single change report."""
    from config import settings
    
    lines = [
        "=" * 70,
        f"CIP-010 CHANGE {status.upper()} REPORT",
        f"CIP-010 Baseline Engine v{settings.APP_VERSION}",
        "=" * 70,
        "",
        f"Timestamp:        {datetime.utcnow().isoformat()}",
        f"Reviewed By:      {user.full_name} ({user.username})",
        f"Status:           {status.upper()}",
        "",
        "-" * 40,
        "ASSET INFORMATION",
        "-" * 40,
        f"Asset Name:       {asset.asset_name if asset else 'Unknown'}",
        f"Asset ID:         {change.asset_id}",
        f"Group:            {asset.group_id if asset else 'Unknown'}",
        "",
        "-" * 40,
        "CHANGE DETAILS",
        "-" * 40,
        f"Field:            {change.field_path}",
        f"Change Type:      {change.change_type}",
    ]

    if change.ticket_number:
        lines.append(f"Ticket #:         {change.ticket_number}")

    if change.change_type == "array_modified":
        if change.items_added:
            added = _safe_json_loads(change.items_added) or []
            lines.append(f"\n➕ ADDED ({len(added)} items):")
            for item in added:
                lines.append(f"    + {json.dumps(item) if not isinstance(item, str) else item}")
        if change.items_removed:
            removed = _safe_json_loads(change.items_removed) or []
            lines.append(f"\n➖ REMOVED ({len(removed)} items):")
            for item in removed:
                lines.append(f"    - {json.dumps(item) if not isinstance(item, str) else item}")
    else:
        if change.old_value:
            lines.append(f"Old Value:        {change.old_value}")
        if change.new_value:
            lines.append(f"New Value:        {change.new_value}")
    
    if change.resolution_notes:
        lines.extend([
            "",
            "-" * 40,
            "RESOLUTION NOTES",
            "-" * 40,
            change.resolution_notes
        ])
    
    if status == "rejected":
        lines.extend([
            "",
            "⚠️  BASELINE UNCHANGED - Requires Investigation",
        ])
    elif status == "approved":
        lines.extend([
            "",
            "✅ BASELINE PROMOTED - New configuration is now the baseline",
        ])
    
    lines.extend([
        "",
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ])
    
    return "\n".join(lines)


def _format_bulk_report(changes: list, status: str, user: User, affected_assets: list) -> str:
    """Format a bulk change report."""
    from config import settings
    
    lines = [
        "=" * 70,
        f"CIP-010 BULK {status.upper()} REPORT",
        f"CIP-010 Baseline Engine v{settings.APP_VERSION}",
        "=" * 70,
        "",
        f"Timestamp:        {datetime.utcnow().isoformat()}",
        f"Reviewed By:      {user.full_name} ({user.username})",
        f"Status:           {status.upper()}",
        f"Changes Affected: {len(changes)}",
        f"Assets Affected:  {len(affected_assets)}",
        "",
        "-" * 40,
        "AFFECTED ASSETS",
        "-" * 40,
    ]
    
    for asset in affected_assets:
        lines.append(f"  • {asset['name']} (ID: {asset['id']})")
    
    if changes:
        change = changes[0]
        lines.extend([
            "",
            "-" * 40,
            "CHANGE DETAILS",
            "-" * 40,
            f"Field:            {change.field_path}",
            f"Change Type:      {change.change_type}",
        ])
        if change.ticket_number:
            lines.append(f"Ticket #:         {change.ticket_number}")

    lines.extend([
        "",
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ])
    
    return "\n".join(lines)
