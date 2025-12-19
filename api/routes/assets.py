"""
Asset management routes for CIP-010 Baseline Engine.
"""
from datetime import datetime, timedelta
from typing import Optional
import json
import hashlib

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import get_db, Asset, AssetState, BaselineSnapshot, Change, ChangeStatus, AuditLog, Group
from core import compare_configurations, compute_config_hash, parse_json_content, parse_json_dict
from api.schemas import (
    AssetResponse, AssetDetail, AssetCreate, AssetGroupAssignment,
    FileUploadResult, BulkUploadResult
)
from api.routes.auth import get_current_user, get_current_admin, verify_password, User

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


@router.get("")
async def list_assets(
    group_id: Optional[str] = None,
    state: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all assets with optional filtering."""
    query = db.query(Asset)

    if group_id:
        query = query.filter(Asset.group_id == group_id)

    if state:
        query = query.filter(Asset.current_state == state)

    # Update days_in_state before returning
    assets = query.all()
    result = []
    for asset in assets:
        asset.update_days_in_state()

        # Get the most recent promoted baseline date
        current_baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.promoted_at != None
        ).order_by(BaselineSnapshot.promoted_at.desc()).first()

        # Get the latest ticket # (from pending changes, field_tickets_json, or baseline)
        latest_ticket = None

        # First check pending/approved changes that haven't been finalized yet
        latest_change_with_ticket = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.ticket_number != None
        ).order_by(Change.status_changed_at.desc()).first()

        if latest_change_with_ticket and latest_change_with_ticket.ticket_number:
            latest_ticket = latest_change_with_ticket.ticket_number
        elif current_baseline:
            # Check field_tickets_json for persisted field tickets
            if current_baseline.field_tickets_json:
                field_tickets = json.loads(current_baseline.field_tickets_json)
                if field_tickets:
                    # Get any field ticket (they're all from recent approved changes)
                    latest_ticket = next(iter(field_tickets.values()), None)
            # Fall back to baseline ticket
            if not latest_ticket and current_baseline.ticket_number:
                latest_ticket = current_baseline.ticket_number

        # Build response with baseline_promoted_at
        asset_dict = {
            "id": asset.id,
            "asset_name": asset.asset_name,
            "group_id": asset.group_id,
            "fqdn": asset.fqdn,
            "version": asset.version,
            "current_state": asset.current_state.value if hasattr(asset.current_state, 'value') else asset.current_state,
            "days_in_current_state": asset.days_in_current_state,
            "last_baseline_check": asset.last_baseline_check,
            "last_approved_change": asset.last_approved_change,
            "baseline_promoted_at": current_baseline.promoted_at if current_baseline else None,
            "latest_ticket": latest_ticket,
            # NOTE: compliance_due_date removed in v4.0.0 - timers are now per-change
            "retired_at": asset.retired_at,
            "retired_by": asset.retired_by,
            "retirement_ticket": asset.retirement_ticket,
            "created_at": asset.created_at,
            "updated_at": asset.updated_at,
            "pending_change_count": db.query(Change).filter(
                Change.asset_id == asset.id,
                Change.status == ChangeStatus.PENDING
            ).count()
        }
        result.append(asset_dict)

    db.commit()
    return result


@router.get("/{asset_id}", response_model=AssetDetail)
async def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get asset details including current configuration."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    asset.update_days_in_state()
    
    # Get current baseline config (or pending baseline for new assets)
    current_snapshot = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == True
    ).first()

    # If no promoted baseline, get pending baseline (for new asset review)
    if not current_snapshot:
        current_snapshot = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset_id,
            BaselineSnapshot.promoted_at == None
        ).order_by(BaselineSnapshot.captured_at.desc()).first()
    
    # Get pending change count
    pending_count = db.query(Change).filter(
        Change.asset_id == asset_id,
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    ).count()
    
    db.commit()
    
    return AssetDetail(
        id=asset.id,
        asset_name=asset.asset_name,
        group_id=asset.group_id,
        fqdn=asset.fqdn,
        version=asset.version,
        current_state=asset.current_state.value,
        days_in_current_state=asset.days_in_current_state,
        last_baseline_check=asset.last_baseline_check,
        last_approved_change=asset.last_approved_change,
        # NOTE: compliance_due_date removed in v4.0.0 - timers are now per-change
        retired_at=asset.retired_at,
        retired_by=asset.retired_by,
        retirement_ticket=asset.retirement_ticket,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        current_config=json.loads(current_snapshot.config_json) if current_snapshot else None,
        pending_change_count=pending_count
    )


@router.get("/{asset_id}/effective-baseline")
async def get_effective_baseline(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get the computed effective baseline for an asset.

    The effective baseline is constructed from the change history:
    - Approved changes: new values incorporated
    - Rejected changes: baseline values preserved
    - Investigation/Pending: baseline values shown with status flags

    This represents what the baseline "actually is" after all decisions,
    not just the last ingested config file.
    """
    from services.baseline import compute_effective_baseline, get_baseline_with_pending_overlay

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get the full baseline with pending overlay
    baseline_data = get_baseline_with_pending_overlay(db, asset_id)

    return {
        "asset_id": asset_id,
        "asset_name": asset.asset_name,
        "current_baseline": baseline_data["current_baseline"],
        "preview_if_all_approved": baseline_data["preview_if_all_approved"],
        "field_statuses": baseline_data["field_statuses"],
        "field_tickets": baseline_data["field_tickets"],
        "pending_changes": baseline_data["pending_changes"],
        "baseline_snapshot_id": baseline_data["baseline_snapshot_id"],
        "baseline_promoted_at": baseline_data["baseline_promoted_at"],
        "ticket_number": baseline_data["ticket_number"]
    }


@router.post("/upload", response_model=BulkUploadResult)
async def upload_files(
    files: list[UploadFile] = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Upload one or more baseline JSON files.
    
    Assets are identified by FQDN from within the file content.
    Only files with timestamps newer than the current baseline will be compared.
    
    For new assets: Creates asset and initial baseline (requires group assignment later)
    For existing assets: Compares and creates pending changes (if newer)
    """
    results = BulkUploadResult(
        files_processed=0,
        new_assets=0,
        updated_assets=0,
        errors=[],
        results=[]
    )
    
    for file in files:
        if not file.filename.lower().endswith('.json'):
            results.errors.append(f"{file.filename}: Not a JSON file")
            continue
        
        try:
            content = await file.read()
            parsed = parse_json_content(content.decode('utf-8'), file.filename)
            
            if not parsed:
                results.errors.append(f"{file.filename}: Failed to parse JSON")
                continue
            
            # Require FQDN for asset identification
            if not parsed.fqdn:
                results.errors.append(f"{file.filename}: No FQDN/hostname found in file. Assets must have an fqdn, hostname, or similar field.")
                continue
            
            # Use FQDN as the asset identifier
            asset_identifier = parsed.fqdn
            
            # Check if asset exists (by FQDN stored in asset_name)
            asset = db.query(Asset).filter(Asset.asset_name == asset_identifier).first()
            
            if not asset:
                # New asset - create it
                asset = Asset(
                    asset_name=asset_identifier,  # FQDN is the asset_name
                    fqdn=parsed.fqdn,
                    version=parsed.version,
                    current_state=AssetState.ACTIVE
                )
                db.add(asset)
                db.flush()
                
                # Create initial baseline (pending promotion - not yet official)
                snapshot = BaselineSnapshot(
                    asset_id=asset.id,
                    config_json=json.dumps(parsed.config),
                    config_hash=compute_config_hash(parsed.config),
                    capture_timestamp=parsed.capture_timestamp,
                    source="manual_upload",
                    triggered_by=current_user.username,
                    filename=parsed.filename,
                    is_current_baseline=False,  # Not promoted yet
                    promoted_at=None,
                    promoted_by=None
                )
                db.add(snapshot)

                # Audit log
                audit = AuditLog(
                    user_id=current_user.id,
                    action="create_asset",
                    action_detail=f"Created new asset: {asset_identifier} (pending initial baseline promotion)",
                    asset_id=asset.id
                )
                db.add(audit)
                _send_syslog_event("create_asset", f"Created new asset: {asset_identifier}",
                                   asset_id=asset.id, asset_name=asset_identifier,
                                   user_id=current_user.id, username=current_user.username)

                results.new_assets += 1
                results.results.append(FileUploadResult(
                    filename=file.filename,
                    asset_name=asset_identifier,
                    is_new_asset=True,
                    message="New asset created - review and assign group to promote initial baseline"
                ))
            else:
                # Existing asset - check timestamp before comparing
                current_baseline = db.query(BaselineSnapshot).filter(
                    BaselineSnapshot.asset_id == asset.id,
                    BaselineSnapshot.is_current_baseline == True
                ).first()
                
                if current_baseline:
                    # Check if new file is newer than current baseline
                    baseline_timestamp = current_baseline.capture_timestamp or current_baseline.promoted_at or current_baseline.captured_at
                    new_timestamp = parsed.capture_timestamp
                    
                    if new_timestamp and baseline_timestamp:
                        if new_timestamp <= baseline_timestamp:
                            results.results.append(FileUploadResult(
                                filename=file.filename,
                                asset_name=asset_identifier,
                                is_new_asset=False,
                                changes_detected=0,
                                message=f"Skipped: File timestamp ({new_timestamp.strftime('%Y-%m-%d %H:%M')}) is not newer than baseline ({baseline_timestamp.strftime('%Y-%m-%d %H:%M')})"
                            ))
                            results.files_processed += 1
                            continue
                    
                    # Compare configurations
                    old_config = json.loads(current_baseline.config_json)
                    comparison = compare_configurations(old_config, parsed.config)
                    
                    if comparison.is_identical:
                        results.results.append(FileUploadResult(
                            filename=file.filename,
                            asset_name=asset_identifier,
                            is_new_asset=False,
                            changes_detected=0,
                            message="No changes detected"
                        ))
                    else:
                        # Create new snapshot
                        new_snapshot = BaselineSnapshot(
                            asset_id=asset.id,
                            config_json=json.dumps(parsed.config),
                            config_hash=comparison.new_hash,
                            capture_timestamp=parsed.capture_timestamp,
                            source="manual_upload",
                            triggered_by=current_user.username,
                            filename=parsed.filename,
                            is_current_baseline=False
                        )
                        db.add(new_snapshot)
                        db.flush()
                        
                        # Create or update change records (supersede existing pending changes)
                        for change in comparison.changes:
                            existing = db.query(Change).filter(
                                Change.asset_id == asset.id,
                                Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION]),
                                Change.field_path == change.path
                            ).first()

                            if existing:
                                # Supersede: Update existing change with new value
                                existing.new_value = json.dumps(change.new_value) if change.new_value is not None else None
                                existing.items_added = json.dumps(change.items_added) if change.items_added else None
                                existing.items_removed = json.dumps(change.items_removed) if change.items_removed else None
                                existing.new_snapshot_id = new_snapshot.id
                                existing.change_signature = change.signature
                                existing.change_type = change.change_type.value
                            else:
                                change_record = Change(
                                    asset_id=asset.id,
                                    field_path=change.path,
                                    change_type=change.change_type.value,
                                    old_value=json.dumps(change.old_value) if change.old_value is not None else None,
                                    new_value=json.dumps(change.new_value) if change.new_value is not None else None,
                                    items_added=json.dumps(change.items_added) if change.items_added else None,
                                    items_removed=json.dumps(change.items_removed) if change.items_removed else None,
                                    status=ChangeStatus.PENDING,
                                    change_signature=change.signature,
                                    old_snapshot_id=current_baseline.id,
                                    new_snapshot_id=new_snapshot.id,
                                    compliance_due_date=(datetime.utcnow() + timedelta(days=settings.COMPLIANCE_WINDOW_DAYS)).date()
                                )
                                db.add(change_record)

                        # Audit log
                        audit = AuditLog(
                            user_id=current_user.id,
                            action="upload_changes",
                            action_detail=f"Uploaded {len(comparison.changes)} changes for {asset_identifier}",
                            asset_id=asset.id
                        )
                        db.add(audit)
                        _send_syslog_event("upload_changes", f"Uploaded {len(comparison.changes)} changes for {asset_identifier}",
                                           asset_id=asset.id, asset_name=asset_identifier,
                                           user_id=current_user.id, username=current_user.username,
                                           details={"change_count": len(comparison.changes)})

                        results.updated_assets += 1
                        results.results.append(FileUploadResult(
                            filename=file.filename,
                            asset_name=asset_identifier,
                            is_new_asset=False,
                            changes_detected=len(comparison.changes),
                            message=f"{len(comparison.changes)} changes pending review"
                        ))
                
                # Update metadata
                asset.fqdn = parsed.fqdn or asset.fqdn
                asset.version = parsed.version or asset.version
                asset.updated_at = datetime.utcnow()
            
            results.files_processed += 1
            
        except Exception as e:
            results.errors.append(f"{file.filename}: {str(e)}")
    
    db.commit()
    return results


class ConfigSubmission(BaseModel):
    """Request body for direct JSON config submission."""
    config: dict  # The configuration JSON object
    source_name: Optional[str] = "api_submission"  # Optional source identifier


class ConfigSubmissionResult(BaseModel):
    """Result of a single config submission."""
    asset_name: str
    is_new_asset: bool
    changes_detected: int = 0
    message: str


@router.post("/submit-config", response_model=ConfigSubmissionResult)
async def submit_config(
    submission: ConfigSubmission,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submit a configuration JSON directly via API (no file upload needed).

    This endpoint accepts a JSON configuration in the request body, making it
    easy to integrate with scripts, automation tools, and other systems.

    The config must contain an 'fqdn' or 'hostname' field for asset identification.
    Optionally include 'timestamp' or 'capture_date' for timestamp validation.

    Example request body:
    {
        "config": {
            "fqdn": "server1.example.com",
            "timestamp": "2025-12-16T12:00:00Z",
            "network": { "dns": ["10.0.0.1"] },
            "services": ["ssh", "http"]
        },
        "source_name": "ansible_playbook"
    }

    Example curl command:
    curl -X POST http://localhost:8000/api/assets/submit-config \\
         -H "Authorization: Bearer YOUR_TOKEN" \\
         -H "Content-Type: application/json" \\
         -d '{"config": {"fqdn": "server1.example.com", "network": {...}}}'
    """
    config = submission.config
    source_name = submission.source_name or "api_submission"

    # Parse the config using the existing parser
    parsed = parse_json_dict(config, source_name)

    if not parsed.fqdn:
        raise HTTPException(
            status_code=400,
            detail="Config must contain 'fqdn', 'hostname', or similar field for asset identification"
        )

    asset_identifier = parsed.fqdn

    # Check if asset exists
    asset = db.query(Asset).filter(Asset.asset_name == asset_identifier).first()

    if not asset:
        # New asset - create it
        asset = Asset(
            asset_name=asset_identifier,
            fqdn=parsed.fqdn,
            version=parsed.version,
            current_state=AssetState.ACTIVE
        )
        db.add(asset)
        db.flush()

        # Create initial baseline (pending promotion)
        snapshot = BaselineSnapshot(
            asset_id=asset.id,
            config_json=json.dumps(parsed.config),
            config_hash=compute_config_hash(parsed.config),
            capture_timestamp=parsed.capture_timestamp,
            source=source_name,
            triggered_by=current_user.username,
            filename=source_name,
            is_current_baseline=False,
            promoted_at=None,
            promoted_by=None
        )
        db.add(snapshot)

        # Audit log
        audit = AuditLog(
            user_id=current_user.id,
            action="create_asset",
            action_detail=f"Created new asset via API: {asset_identifier}",
            asset_id=asset.id
        )
        db.add(audit)
        _send_syslog_event("create_asset", f"Created new asset via API: {asset_identifier}",
                          asset_id=asset.id, asset_name=asset_identifier,
                          user_id=current_user.id, username=current_user.username)

        db.commit()

        return ConfigSubmissionResult(
            asset_name=asset_identifier,
            is_new_asset=True,
            changes_detected=0,
            message="New asset created - assign to group to promote initial baseline"
        )

    else:
        # Existing asset - compare with current baseline
        current_baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.is_current_baseline == True
        ).first()

        if not current_baseline:
            raise HTTPException(
                status_code=400,
                detail=f"Asset {asset_identifier} exists but has no promoted baseline. Assign to group first."
            )

        # Check timestamp if both are available
        baseline_timestamp = current_baseline.capture_timestamp or current_baseline.promoted_at or current_baseline.captured_at
        new_timestamp = parsed.capture_timestamp

        if new_timestamp and baseline_timestamp:
            if new_timestamp <= baseline_timestamp:
                return ConfigSubmissionResult(
                    asset_name=asset_identifier,
                    is_new_asset=False,
                    changes_detected=0,
                    message=f"Skipped: Config timestamp ({new_timestamp.strftime('%Y-%m-%d %H:%M')}) is not newer than baseline ({baseline_timestamp.strftime('%Y-%m-%d %H:%M')})"
                )

        # Compare configurations
        old_config = json.loads(current_baseline.config_json)
        comparison = compare_configurations(old_config, parsed.config)

        if comparison.is_identical:
            return ConfigSubmissionResult(
                asset_name=asset_identifier,
                is_new_asset=False,
                changes_detected=0,
                message="No changes detected - config matches current baseline"
            )

        # Create new snapshot for comparison
        new_snapshot = BaselineSnapshot(
            asset_id=asset.id,
            config_json=json.dumps(parsed.config),
            config_hash=comparison.new_hash,
            capture_timestamp=parsed.capture_timestamp,
            source=source_name,
            triggered_by=current_user.username,
            filename=source_name,
            is_current_baseline=False
        )
        db.add(new_snapshot)
        db.flush()

        # Create or update change records
        # If a pending/investigation change already exists for this field, supersede it
        # (update with new value) rather than creating duplicate changes
        for change in comparison.changes:
            existing = db.query(Change).filter(
                Change.asset_id == asset.id,
                Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION]),
                Change.field_path == change.path
            ).first()

            if existing:
                # Supersede: Update existing change with new value
                # Keep original old_value, detected_at, and compliance_due_date
                existing.new_value = json.dumps(change.new_value) if change.new_value is not None else None
                existing.items_added = json.dumps(change.items_added) if change.items_added else None
                existing.items_removed = json.dumps(change.items_removed) if change.items_removed else None
                existing.new_snapshot_id = new_snapshot.id
                existing.change_signature = change.signature
                existing.change_type = change.change_type.value
            else:
                # Create new change record
                change_record = Change(
                    asset_id=asset.id,
                    field_path=change.path,
                    change_type=change.change_type.value,
                    old_value=json.dumps(change.old_value) if change.old_value is not None else None,
                    new_value=json.dumps(change.new_value) if change.new_value is not None else None,
                    items_added=json.dumps(change.items_added) if change.items_added else None,
                    items_removed=json.dumps(change.items_removed) if change.items_removed else None,
                    status=ChangeStatus.PENDING,
                    change_signature=change.signature,
                    old_snapshot_id=current_baseline.id,
                    new_snapshot_id=new_snapshot.id,
                    compliance_due_date=(datetime.utcnow() + timedelta(days=settings.COMPLIANCE_WINDOW_DAYS)).date()
                )
                db.add(change_record)

        # Audit log
        audit = AuditLog(
            user_id=current_user.id,
            action="config_submitted",
            action_detail=f"Config submitted via API for {asset_identifier}: {len(comparison.changes)} changes detected",
            asset_id=asset.id
        )
        db.add(audit)
        _send_syslog_event("config_submitted", f"Config submitted via API: {len(comparison.changes)} changes",
                          asset_id=asset.id, asset_name=asset_identifier,
                          user_id=current_user.id, username=current_user.username)

        # Update asset metadata
        asset.fqdn = parsed.fqdn or asset.fqdn
        asset.version = parsed.version or asset.version
        asset.updated_at = datetime.utcnow()

        db.commit()

        return ConfigSubmissionResult(
            asset_name=asset_identifier,
            is_new_asset=False,
            changes_detected=len(comparison.changes),
            message=f"Detected {len(comparison.changes)} change(s) - review pending"
        )


@router.put("/{asset_id}/group", response_model=AssetResponse)
async def assign_group(
    asset_id: int,
    assignment: AssetGroupAssignment,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Assign asset to a group and promote initial baseline if pending."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Verify group exists
    group = db.query(Group).filter(Group.id == assignment.group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    old_group = asset.group_id
    asset.group_id = assignment.group_id

    # Check if there's a pending (unpromoted) baseline that needs promotion
    pending_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == False,
        BaselineSnapshot.promoted_at == None
    ).first()

    # Require ticket number when promoting initial baseline
    if pending_baseline and (not assignment.ticket_number or not assignment.ticket_number.strip()):
        raise HTTPException(status_code=400, detail="Ticket number is required when promoting initial baseline")

    promoted_baseline = False
    if pending_baseline:
        # Promote the pending baseline
        pending_baseline.is_current_baseline = True
        pending_baseline.promoted_at = datetime.utcnow()
        pending_baseline.promoted_by = current_user.username
        pending_baseline.ticket_number = assignment.ticket_number  # Save change management ticket #
        promoted_baseline = True

        # Set asset state to COMPLIANT now that baseline is established
        asset.current_state = AssetState.COMPLIANT

        # Audit log for promotion
        promote_audit = AuditLog(
            user_id=current_user.id,
            action="promote_initial_baseline",
            action_detail=f"Promoted initial baseline for {asset.asset_name}" +
                         (f" (Ticket: {assignment.ticket_number})" if assignment.ticket_number else ""),
            asset_id=asset.id,
            details_json=json.dumps({"ticket_number": assignment.ticket_number}) if assignment.ticket_number else None
        )
        db.add(promote_audit)
        _send_syslog_event("promote_initial_baseline", f"Promoted initial baseline for {asset.asset_name}",
                           asset_id=asset.id, asset_name=asset.asset_name,
                           user_id=current_user.id, username=current_user.username,
                           details={"ticket_number": assignment.ticket_number} if assignment.ticket_number else None)

    # Audit log for group assignment
    audit = AuditLog(
        user_id=current_user.id,
        action="assign_group",
        action_detail=f"Changed group from {old_group} to {assignment.group_id}" +
                      (" and promoted initial baseline" if promoted_baseline else ""),
        asset_id=asset.id
    )
    db.add(audit)
    _send_syslog_event("assign_group", f"Changed group from {old_group} to {assignment.group_id}",
                       asset_id=asset.id, asset_name=asset.asset_name,
                       user_id=current_user.id, username=current_user.username,
                       details={"old_group": old_group, "new_group": assignment.group_id})

    db.commit()
    db.refresh(asset)

    return asset


@router.put("/{asset_id}/config")
async def update_config(
    asset_id: int,
    config: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submit manual configuration edit for review.
    Creates a new snapshot and change records that go through the approval workflow.
    Does NOT directly update the baseline - changes must be approved first.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get current baseline
    current_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == True
    ).first()

    if not current_baseline:
        raise HTTPException(status_code=400, detail="No current baseline exists. Cannot submit manual edit.")

    # Get old config for comparison
    old_config = json.loads(current_baseline.config_json)
    old_config_hash = current_baseline.config_hash

    # Check if configs are actually different
    new_config_hash = compute_config_hash(config)
    if new_config_hash == old_config_hash:
        return {"message": "No changes detected", "asset_id": asset_id, "changes_created": 0}

    # Create new snapshot (NOT marked as current baseline - pending review)
    new_snapshot = BaselineSnapshot(
        asset_id=asset.id,
        config_json=json.dumps(config),
        config_hash=new_config_hash,
        source="manual_edit",
        triggered_by=current_user.username,
        is_current_baseline=False  # Will be promoted when changes are approved
    )
    db.add(new_snapshot)
    db.flush()  # Get the snapshot ID

    # Compare configurations and create Change records
    comparison = compare_configurations(old_config, config)
    changes_created = 0

    for change in comparison.changes:
        # Compute signature for grouping
        change_sig = Change.compute_signature(
            change.path,
            change.change_type.value,
            change.old_value,
            change.new_value
        )

        change_record = Change(
            asset_id=asset.id,
            field_path=change.path,
            change_type=change.change_type.value,
            old_value=json.dumps(change.old_value) if change.old_value is not None else None,
            new_value=json.dumps(change.new_value) if change.new_value is not None else None,
            items_added=json.dumps(change.items_added) if change.items_added else None,
            items_removed=json.dumps(change.items_removed) if change.items_removed else None,
            status=ChangeStatus.PENDING,
            old_snapshot_id=current_baseline.id,
            new_snapshot_id=new_snapshot.id,
            change_signature=change_sig,
            compliance_due_date=(datetime.utcnow() + timedelta(days=settings.COMPLIANCE_WINDOW_DAYS)).date()
        )
        db.add(change_record)
        changes_created += 1

    # Audit log with detailed change information
    changed_fields = [{"field": c.path, "old_value": c.old_value, "new_value": c.new_value}
                      for c in comparison.changes]

    audit_details = {
        "old_config_hash": old_config_hash,
        "new_config_hash": new_config_hash,
        "fields_changed": len(changed_fields),
        "changes": changed_fields[:20],
        "total_changes": len(changed_fields),
        "new_snapshot_id": new_snapshot.id,
        "requires_approval": True
    }

    audit = AuditLog(
        user_id=current_user.id,
        action="manual_config_edit",
        action_detail=f"Proposed {changes_created} change(s) via manual edit",
        asset_id=asset.id,
        details_json=json.dumps(audit_details)
    )
    db.add(audit)
    _send_syslog_event("manual_config_edit", f"Proposed {changes_created} change(s) via manual edit",
                       asset_id=asset.id, asset_name=asset.asset_name,
                       user_id=current_user.id, username=current_user.username,
                       details={"change_count": changes_created})

    db.commit()

    return {
        "message": f"Manual edit submitted for review. {changes_created} change(s) created.",
        "asset_id": asset_id,
        "changes_created": changes_created,
        "requires_approval": True
    }


class DeleteAssetRequest(BaseModel):
    password: str


@router.post("/{asset_id}/delete")
async def delete_asset(
    asset_id: int,
    request: DeleteAssetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Delete an asset and all related data.

    Requires admin role and password confirmation.
    Audit logs are preserved after deletion.
    """
    # Verify password
    from database import User as UserModel
    user = db.query(UserModel).filter(UserModel.id == current_user.id).first()
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    asset_name = asset.asset_name
    group_id = asset.group_id

    # Audit log before deletion - include asset_name for persistence
    audit = AuditLog(
        user_id=current_user.id,
        action="delete_asset",
        action_detail=f"Deleted asset: {asset_name}",
        asset_id=asset_id,
        asset_name=asset_name,  # Preserved after deletion
        details_json=json.dumps({"asset_name": asset_name, "group_id": group_id})
    )
    db.add(audit)
    _send_syslog_event("delete_asset", f"Deleted asset: {asset_name}",
                       asset_name=asset_name,
                       user_id=current_user.id, username=current_user.username,
                       details={"group_id": group_id})

    # Delete asset (cascades to snapshots and changes)
    db.delete(asset)
    db.commit()

    return {"message": f"Asset '{asset_name}' deleted"}


@router.get("/{asset_id}/snapshots")
async def get_asset_snapshots(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all baseline snapshots for an asset (time-series history)."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    snapshots = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id
    ).order_by(BaselineSnapshot.captured_at.desc()).all()
    
    return [
        {
            "id": s.id,
            "captured_at": s.captured_at.isoformat(),
            "config_hash": s.config_hash,
            "source": s.source,
            "triggered_by": s.triggered_by,
            "is_current_baseline": s.is_current_baseline,
            "promoted_at": s.promoted_at.isoformat() if s.promoted_at else None
        }
        for s in snapshots
    ]


@router.get("/{asset_id}/audit-logs")
async def get_asset_audit_logs(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get audit logs for an asset.
    Shows all actions taken on this asset including manual edits.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Query logs that either have this asset_id OR mention this asset in details_json
    from sqlalchemy import or_
    logs = db.query(AuditLog).filter(
        or_(
            AuditLog.asset_id == asset_id,
            AuditLog.details_json.like(f'%"id": {asset_id},%'),  # Match in affected_assets
            AuditLog.details_json.like(f'%"id": {asset_id}}}%')  # Match at end of list
        )
    ).order_by(AuditLog.timestamp.desc()).limit(100).all()

    result = []
    for log in logs:
        # Get username from user_id
        username = None
        if log.user_id:
            user = db.query(User).filter(User.id == log.user_id).first()
            username = user.username if user else f"user_{log.user_id}"

        result.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "username": username,
            "action": log.action,
            "action_detail": log.action_detail,
            "details": json.loads(log.details_json) if log.details_json else None,
            "is_admin_only": log.action in ["manual_config_edit", "delete_asset"],
            "report_id": log.report_id
        })

    return result


@router.post("/{asset_id}/rename")
async def rename_asset(
    asset_id: int,
    new_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Request to rename an asset (change its FQDN/unique identifier).

    This creates a pending change that must be approved before the rename takes effect.
    The asset_name/FQDN is part of the baseline configuration, so changes require
    the same approval workflow as other baseline modifications.

    The change will appear in the pending changes review with field_path "__asset_name__".
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if not new_name or not new_name.strip():
        raise HTTPException(status_code=400, detail="New name is required")

    new_name = new_name.strip()
    old_name = asset.asset_name

    # Check if new name is different
    if new_name == old_name:
        raise HTTPException(status_code=400, detail="New name is the same as current name")

    # Check if new name already exists
    existing = db.query(Asset).filter(Asset.asset_name == new_name).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"An asset with name '{new_name}' already exists")

    # Check if there's already a pending rename for this asset
    existing_rename = db.query(Change).filter(
        Change.asset_id == asset_id,
        Change.field_path == "__asset_name__",
        Change.status == "pending"
    ).first()
    if existing_rename:
        raise HTTPException(status_code=400, detail="There is already a pending rename request for this asset. Please approve or reject it first.")

    # Compute signature for the rename change (same algorithm as core/comparison.py)
    sig_parts = ["__asset_name__", "modified", json.dumps(old_name), json.dumps(new_name)]
    sig_str = "|".join(sig_parts)
    change_signature = hashlib.sha256(sig_str.encode()).hexdigest()[:16]

    # Create a pending change for the rename (requires approval)
    change = Change(
        asset_id=asset.id,
        field_path="__asset_name__",
        change_type="modified",
        old_value=old_name,
        new_value=new_name,
        status="pending",
        detected_at=datetime.utcnow(),
        change_signature=change_signature,
        compliance_due_date=(datetime.utcnow() + timedelta(days=settings.COMPLIANCE_WINDOW_DAYS)).date()
    )
    db.add(change)

    # Create audit log for the rename request
    audit = AuditLog(
        user_id=current_user.id,
        action="rename_asset_requested",
        action_detail=f"Requested rename: '{old_name}' → '{new_name}' (pending approval)",
        asset_id=asset.id,
        details_json=json.dumps({
            "old_name": old_name,
            "new_name": new_name,
            "requested_by": current_user.username,
            "requested_at": datetime.utcnow().isoformat()
        })
    )
    db.add(audit)

    _send_syslog_event("rename_asset_requested", f"Requested rename: '{old_name}' → '{new_name}' (pending approval)",
                       asset_id=asset.id, asset_name=old_name,
                       user_id=current_user.id, username=current_user.username,
                       details={"old_name": old_name, "new_name": new_name})

    db.commit()

    return {
        "message": f"Rename request submitted for approval",
        "asset_id": asset.id,
        "old_name": old_name,
        "new_name": new_name,
        "requested_by": current_user.username,
        "status": "pending_approval",
        "change_id": change.id
    }


@router.post("/{asset_id}/retire")
async def retire_asset(
    asset_id: int,
    retirement_ticket: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retire an asset. Retired assets:
    - Are excluded from scheduled compliance checks
    - Are excluded from change detection automation
    - Retain all historical data for audit purposes
    - Can be filtered out in the UI

    Requires a retirement ticket number for audit trail.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if asset.current_state == AssetState.RETIRED:
        raise HTTPException(status_code=400, detail="Asset is already retired")

    if not retirement_ticket or not retirement_ticket.strip():
        raise HTTPException(status_code=400, detail="Retirement ticket number is required")

    # Store previous state for audit
    previous_state = asset.current_state.value

    # Retire the asset
    asset.current_state = AssetState.RETIRED
    asset.state_changed_at = datetime.utcnow()
    asset.retired_at = datetime.utcnow()
    asset.retired_by = current_user.username
    asset.retirement_ticket = retirement_ticket.strip()

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="retire_asset",
        action_detail=f"Retired asset: {asset.asset_name} (Ticket: {retirement_ticket.strip()})",
        asset_id=asset.id,
        details_json=json.dumps({
            "previous_state": previous_state,
            "retirement_ticket": retirement_ticket.strip()
        })
    )
    db.add(audit)
    _send_syslog_event("retire_asset", f"Retired asset: {asset.asset_name}",
                       asset_id=asset.id, asset_name=asset.asset_name,
                       user_id=current_user.id, username=current_user.username,
                       details={"ticket_number": retirement_ticket.strip(), "previous_state": previous_state})

    db.commit()
    db.refresh(asset)

    return {
        "message": f"Asset '{asset.asset_name}' has been retired",
        "asset_id": asset.id,
        "retirement_ticket": asset.retirement_ticket,
        "retired_at": asset.retired_at.isoformat(),
        "retired_by": asset.retired_by
    }


@router.post("/{asset_id}/unretire")
async def unretire_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Restore a retired asset to active status.
    The asset will be included in scheduled checks again.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if asset.current_state != AssetState.RETIRED:
        raise HTTPException(status_code=400, detail="Asset is not retired")

    # Store retirement info for audit
    previous_ticket = asset.retirement_ticket
    previous_retired_at = asset.retired_at.isoformat() if asset.retired_at else None

    # Restore the asset to active (or compliant if it has an approved baseline)
    has_baseline = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.asset_id == asset_id,
        BaselineSnapshot.is_current_baseline == True
    ).first()

    asset.current_state = AssetState.COMPLIANT if has_baseline else AssetState.ACTIVE
    asset.state_changed_at = datetime.utcnow()
    # Keep retirement history fields for audit trail, don't clear them

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="unretire_asset",
        action_detail=f"Restored asset from retirement: {asset.asset_name}",
        asset_id=asset.id,
        details_json=json.dumps({
            "previous_retirement_ticket": previous_ticket,
            "previous_retired_at": previous_retired_at,
            "new_state": asset.current_state.value
        })
    )
    db.add(audit)
    _send_syslog_event("unretire_asset", f"Restored asset from retirement: {asset.asset_name}",
                       asset_id=asset.id, asset_name=asset.asset_name,
                       user_id=current_user.id, username=current_user.username,
                       details={"new_state": asset.current_state.value})

    db.commit()
    db.refresh(asset)

    return {
        "message": f"Asset '{asset.asset_name}' has been restored from retirement",
        "asset_id": asset.id,
        "new_state": asset.current_state.value
    }


@router.post("/admin/backfill-tickets")
async def backfill_tickets(
    ticket_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """One-time admin endpoint to backfill ticket numbers for existing data."""
    # Update baseline snapshots
    snapshots_updated = db.query(BaselineSnapshot).filter(
        BaselineSnapshot.ticket_number == None
    ).update({"ticket_number": ticket_number})

    # Update changes
    changes_updated = db.query(Change).filter(
        Change.ticket_number == None
    ).update({"ticket_number": ticket_number})

    db.commit()

    return {
        "message": f"Backfill complete",
        "baseline_snapshots_updated": snapshots_updated,
        "changes_updated": changes_updated,
        "ticket_number": ticket_number
    }
