"""
Report management routes for CIP-010 Baseline Engine.

All authenticated users can view reports and compliance check history.
"""
from typing import Optional
from datetime import datetime, date, timedelta
import json
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from database import get_db, Report, ReportType, ScheduledCheck, CheckStatus, Asset, Change, ChangeStatus, AssetState, Group, SystemSetting, AuditLog
from config import settings
from api.schemas import ReportResponse
from api.routes.auth import get_current_user, User

router = APIRouter()


def get_compliance_thresholds(db: Session) -> dict:
    """Get compliance thresholds from database with fallback to config defaults."""
    def get_setting(key: str, default: int) -> int:
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if setting and setting.value:
            try:
                return int(setting.value)
            except ValueError:
                return default
        return default

    return {
        "compliance_window_days": get_setting("compliance_window_days", settings.COMPLIANCE_WINDOW_DAYS),
        "green_threshold": get_setting("green_threshold_days", settings.GREEN_THRESHOLD_DAYS),
        "yellow_threshold": get_setting("yellow_threshold_days", settings.YELLOW_THRESHOLD_DAYS),
        "critical_threshold": get_setting("critical_threshold_days", settings.CRITICAL_THRESHOLD_DAYS),
    }


def determine_status(days_remaining: int, thresholds: dict) -> str:
    """Determine status based on days remaining and thresholds."""
    if days_remaining <= 0:
        return "overdue"
    elif days_remaining <= thresholds["critical_threshold"]:
        return "critical"
    elif days_remaining <= thresholds["yellow_threshold"]:
        return "warning"
    elif days_remaining <= thresholds["green_threshold"]:
        return "on_track"
    else:
        return "on_track"


# ============================================================
# SCHEDULED CHECKS (must come before /{report_id})
# ============================================================

@router.get("/scheduled-checks")
async def list_scheduled_checks(
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List recent scheduled compliance checks."""
    checks = db.query(ScheduledCheck).order_by(
        ScheduledCheck.scheduled_date.desc()
    ).limit(limit).all()

    return [
        {
            "id": c.id,
            "scheduled_date": c.scheduled_date.isoformat(),
            "executed_at": c.executed_at.isoformat() if c.executed_at else None,
            "status": c.status.value,
            "trigger_type": getattr(c, 'trigger_type', 'scheduled') or 'scheduled',
            "triggered_by": getattr(c, 'triggered_by', None),
            "assets_checked": c.assets_checked,
            "changes_detected": c.changes_detected,
            "assets_unchanged": c.assets_unchanged,
            "assets_in_investigation": c.assets_in_investigation,
            "aggregate_report_id": c.aggregate_report_id
        }
        for c in checks
    ]


@router.get("/scheduled-checks/{check_id}")
async def get_scheduled_check(
    check_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get details of a specific scheduled check."""
    check = db.query(ScheduledCheck).filter(ScheduledCheck.id == check_id).first()
    if not check:
        raise HTTPException(status_code=404, detail="Scheduled check not found")

    # Get the aggregate report
    report = None
    if check.aggregate_report_id:
        report = db.query(Report).filter(Report.id == check.aggregate_report_id).first()

    # Parse investigated assets JSON
    investigated_assets = []
    if hasattr(check, 'investigated_assets_json') and check.investigated_assets_json:
        try:
            investigated_assets = json.loads(check.investigated_assets_json)
        except json.JSONDecodeError:
            pass

    return {
        "id": check.id,
        "scheduled_date": check.scheduled_date.isoformat(),
        "executed_at": check.executed_at.isoformat() if check.executed_at else None,
        "status": check.status.value,
        "trigger_type": getattr(check, 'trigger_type', 'scheduled') or 'scheduled',
        "triggered_by": getattr(check, 'triggered_by', None),
        "assets_checked": check.assets_checked,
        "changes_detected": check.changes_detected,
        "assets_unchanged": check.assets_unchanged,
        "assets_in_investigation": check.assets_in_investigation,
        "investigated_assets": investigated_assets,
        "error_message": check.error_message,
        "report": {
            "id": report.id,
            "title": report.title,
            "content": report.report_content,
            "generated_at": report.generated_at.isoformat()
        } if report else None
    }


# ============================================================
# COMPLIANCE DASHBOARD
# ============================================================

@router.get("/compliance/summary")
async def get_compliance_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get compliance summary for the dashboard.

    Any authenticated user can view this.
    """
    from database import AssetState

    # Get latest scheduled check
    latest_check = db.query(ScheduledCheck).filter(
        ScheduledCheck.status == CheckStatus.COMPLETED
    ).order_by(ScheduledCheck.executed_at.desc()).first()

    # Count assets by state (exclude retired from totals)
    # States are MUTUALLY EXCLUSIVE: compliant + awaiting_review + investigation + failed = total
    total_assets = db.query(Asset).filter(
        Asset.current_state != AssetState.RETIRED
    ).count()

    # Assets with investigation changes (based on change status, not asset state)
    # This counts assets that have at least one change with status=INVESTIGATION
    asset_ids_with_investigation = db.query(Change.asset_id).filter(
        Change.status == ChangeStatus.INVESTIGATION
    ).distinct().subquery()

    investigation_assets = db.query(Asset).filter(
        Asset.id.in_(asset_ids_with_investigation)
    ).count()

    # Assets in failed state
    failed_assets = db.query(Asset).filter(
        Asset.current_state == AssetState.FAILED
    ).count()

    # Assets with pending changes (awaiting review) - not in investigation/failed
    # These are COMPLIANT/ACTIVE assets that have unreviewed changes
    asset_ids_with_pending = db.query(Change.asset_id).filter(
        Change.status == ChangeStatus.PENDING
    ).distinct().subquery()

    assets_awaiting_review = db.query(Asset).filter(
        Asset.id.in_(asset_ids_with_pending),
        Asset.current_state.notin_([AssetState.INVESTIGATION, AssetState.FAILED, AssetState.RETIRED])
    ).count()

    # Compliant assets = ACTIVE/COMPLIANT state with NO pending changes
    compliant_assets = db.query(Asset).filter(
        or_(Asset.current_state == AssetState.ACTIVE,
            Asset.current_state == AssetState.COMPLIANT),
        ~Asset.id.in_(asset_ids_with_pending)
    ).count()

    # Count open investigations (changes in investigation status)
    open_investigations = db.query(Change).filter(
        Change.status == ChangeStatus.INVESTIGATION
    ).count()

    # Count pending changes
    pending_changes = db.query(Change).filter(
        Change.status == ChangeStatus.PENDING
    ).count()

    return {
        "total_assets": total_assets,
        "compliant_assets": compliant_assets,
        "assets_awaiting_review": assets_awaiting_review,
        "investigation_assets": investigation_assets,
        "failed_assets": failed_assets,
        "open_investigations": open_investigations,
        "pending_changes": pending_changes,
        "last_check": {
            "id": latest_check.id,
            "date": latest_check.scheduled_date.isoformat(),
            "executed_at": latest_check.executed_at.isoformat() if latest_check.executed_at else None,
            "assets_checked": latest_check.assets_checked,
            "changes_detected": latest_check.changes_detected,
            "report_id": latest_check.aggregate_report_id
        } if latest_check else None
    }


@router.get("/compliance/investigations")
async def get_open_investigations(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all open investigations.

    Shows changes in INVESTIGATION status with details about when discovered
    and how long the investigation has been open.
    """
    investigations = db.query(Change).filter(
        Change.status == ChangeStatus.INVESTIGATION
    ).order_by(Change.investigation_started_at.desc()).limit(limit).all()

    results = []
    for inv in investigations:
        asset = db.query(Asset).filter(Asset.id == inv.asset_id).first()

        results.append({
            "change_id": inv.id,
            "asset_id": inv.asset_id,
            "asset_name": asset.asset_name if asset else "Unknown",
            "group_id": asset.group_id if asset else None,
            "field_path": inv.field_path,
            "change_type": inv.change_type,
            "old_value": json.loads(inv.old_value) if inv.old_value else None,
            "new_value": json.loads(inv.new_value) if inv.new_value else None,
            "investigation_started_at": inv.investigation_started_at.isoformat() if inv.investigation_started_at else None,
            "days_in_investigation": inv.days_in_investigation or 0,
            "detected_at": inv.detected_at.isoformat() if inv.detected_at else None
        })

    return results


@router.get("/compliance/investigations-detail")
async def get_investigations_detail(
    as_of_date: Optional[str] = Query(None, description="Date in YYYY-MM-DD format, defaults to today"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get detailed investigation tracking with compliance deadlines.

    Returns all assets in investigation state with:
    - Investigation start date (35-day timer start)
    - Compliance due date
    - Days remaining until non-compliance
    - Status (on_track, warning, critical, overdue)
    """
    # Parse date or use today
    if as_of_date:
        try:
            check_date = datetime.strptime(as_of_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    else:
        check_date = date.today()

    # Get compliance thresholds from settings
    thresholds = get_compliance_thresholds(db)

    # Get all assets that have investigation-status changes
    # Query based on changes first, not asset state (which can get out of sync)
    asset_ids_with_investigation = db.query(Change.asset_id).filter(
        Change.status == ChangeStatus.INVESTIGATION
    ).distinct().all()

    asset_ids = [a[0] for a in asset_ids_with_investigation]
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all() if asset_ids else []

    # Get group info for team names
    groups = {g.id: g.name for g in db.query(Group).all()}

    investigations = []
    summary = {"total": 0, "on_track": 0, "warning": 0, "critical": 0, "overdue": 0}

    for asset in assets:
        # Get investigation changes for this asset
        changes = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.status == ChangeStatus.INVESTIGATION
        ).all()

        if not changes:
            continue

        # Find earliest investigation start
        earliest_start = min(
            (c.investigation_started_at for c in changes if c.investigation_started_at),
            default=None
        )

        # Find earliest compliance due date from changes
        earliest_due_date = min(
            (c.compliance_due_date for c in changes if c.compliance_due_date),
            default=None
        )

        # Calculate days remaining
        if earliest_due_date:
            days_remaining = (earliest_due_date - check_date).days
        elif earliest_start:
            # Calculate from investigation start if no due date set
            due_date = (earliest_start + timedelta(days=thresholds["compliance_window_days"])).date()
            days_remaining = (due_date - check_date).days
        else:
            days_remaining = thresholds["compliance_window_days"]

        # Determine status using configurable thresholds
        status = determine_status(days_remaining, thresholds)
        summary[status] += 1
        summary["total"] += 1

        investigations.append({
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "group_id": asset.group_id,
            "group_name": groups.get(asset.group_id, "Unassigned"),
            "investigation_started_at": earliest_start.isoformat() if earliest_start else None,
            "compliance_due_date": earliest_due_date.isoformat() if earliest_due_date else None,
            "days_remaining": days_remaining,
            "status": status,
            "change_count": len(changes),
            "changes": [
                {
                    "id": c.id,
                    "field": c.field_path,
                    "type": c.change_type,
                    "detected_at": c.detected_at.isoformat() if c.detected_at else None
                }
                for c in changes
            ]
        })

    # Sort by days remaining (most urgent first)
    investigations.sort(key=lambda x: x["days_remaining"])

    return {
        "as_of_date": check_date.isoformat(),
        "compliance_window_days": thresholds["compliance_window_days"],
        "thresholds": {
            "green": thresholds["green_threshold"],
            "yellow": thresholds["yellow_threshold"],
            "critical": thresholds["critical_threshold"]
        },
        "investigations": investigations,
        "summary": summary
    }


@router.get("/compliance/historical")
async def get_historical_investigations(
    query_date: str = Query(..., description="Date in YYYY-MM-DD format"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get investigation status as it was on a specific historical date.

    Shows which assets were in investigation on that date and their status.
    """
    try:
        check_date = datetime.strptime(query_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    check_datetime = datetime.combine(check_date, datetime.max.time())

    # Find changes that were in investigation on that date
    # A change was in investigation if:
    # - investigation_started_at <= check_date
    # - AND (status_changed_at > check_date OR status is still INVESTIGATION)
    investigations = db.query(Change, Asset).join(Asset).filter(
        Change.investigation_started_at <= check_datetime,
        or_(
            Change.status == ChangeStatus.INVESTIGATION,
            Change.status_changed_at > check_datetime
        )
    ).all()

    # Get compliance thresholds from settings
    thresholds = get_compliance_thresholds(db)

    # Get group info
    groups = {g.id: g.name for g in db.query(Group).all()}

    # Group by asset
    asset_map = {}
    for change, asset in investigations:
        if asset.id not in asset_map:
            # Calculate days remaining as of that date
            if change.investigation_started_at:
                due_date = (change.investigation_started_at + timedelta(days=thresholds["compliance_window_days"])).date()
                days_remaining = (due_date - check_date).days
            else:
                days_remaining = thresholds["compliance_window_days"]

            # Determine status using configurable thresholds
            status = determine_status(days_remaining, thresholds)

            asset_map[asset.id] = {
                "asset_id": asset.id,
                "asset_name": asset.asset_name,
                "group_id": asset.group_id,
                "group_name": groups.get(asset.group_id, "Unassigned"),
                "investigation_started_at": change.investigation_started_at.isoformat() if change.investigation_started_at else None,
                "days_remaining": days_remaining,
                "status": status,
                "changes": []
            }

        asset_map[asset.id]["changes"].append({
            "id": change.id,
            "field": change.field_path,
            "type": change.change_type
        })

    results = list(asset_map.values())
    results.sort(key=lambda x: x["days_remaining"])

    return {
        "query_date": check_date.isoformat(),
        "assets_in_investigation": len(results),
        "investigations": results
    }


@router.get("/compliance/pnci-report")
async def generate_pnci_report(
    report_date: Optional[str] = Query(None, description="Date in YYYY-MM-DD format, defaults to today"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate PNCI/Extent of Condition report for compliance documentation.

    Returns a formatted report with all assets in investigation or failed state,
    grouped by team, with compliance deadline information.
    """
    # Parse date or use today
    if report_date:
        try:
            check_date = datetime.strptime(report_date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    else:
        check_date = date.today()

    # Get compliance thresholds from settings
    thresholds = get_compliance_thresholds(db)

    # Get all assets in investigation or failed state
    assets = db.query(Asset).filter(
        Asset.current_state.in_([AssetState.INVESTIGATION, AssetState.FAILED])
    ).all()

    # Get group info
    groups = {g.id: {"name": g.name, "color": g.color} for g in db.query(Group).all()}

    # Build report data grouped by team
    by_team = {}
    recommendations = []
    total_overdue = 0
    total_critical = 0

    for asset in assets:
        # Get changes for this asset
        changes = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.status.in_([ChangeStatus.INVESTIGATION, ChangeStatus.PENDING])
        ).all()

        # Find earliest investigation start
        earliest_start = None
        earliest_due_date = None
        for c in changes:
            if c.investigation_started_at:
                if earliest_start is None or c.investigation_started_at < earliest_start:
                    earliest_start = c.investigation_started_at
            if c.compliance_due_date:
                if earliest_due_date is None or c.compliance_due_date < earliest_due_date:
                    earliest_due_date = c.compliance_due_date

        # Calculate days remaining
        if earliest_due_date:
            days_remaining = (earliest_due_date - check_date).days
        elif earliest_start:
            due_date = (earliest_start + timedelta(days=thresholds["compliance_window_days"])).date()
            days_remaining = (due_date - check_date).days
        else:
            days_remaining = thresholds["compliance_window_days"]

        # Track for recommendations using configurable thresholds
        if days_remaining <= 0:
            total_overdue += 1
        elif days_remaining <= thresholds["critical_threshold"]:
            total_critical += 1
            recommendations.append(f"Asset '{asset.asset_name}' requires immediate attention - {days_remaining} days until non-compliance")

        team_id = asset.group_id or "unassigned"
        team_name = groups.get(team_id, {}).get("name", "Unassigned")

        if team_id not in by_team:
            by_team[team_id] = {
                "team_id": team_id,
                "team_name": team_name,
                "assets": []
            }

        by_team[team_id]["assets"].append({
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "state": asset.current_state.value if hasattr(asset.current_state, 'value') else str(asset.current_state),
            "investigation_started": earliest_start.isoformat() if earliest_start else None,
            "compliance_due_date": earliest_due_date.isoformat() if earliest_due_date else None,
            "days_remaining": days_remaining,
            "change_count": len(changes)
        })

    # Add team-level recommendations
    for team_id, team_data in by_team.items():
        if len(team_data["assets"]) > 2:
            recommendations.append(f"Consider Extent of Condition review for {team_data['team_name']} - {len(team_data['assets'])} assets under investigation")

    # Generate text report
    report_lines = [
        "=" * 70,
        "CIP-010 COMPLIANCE STATUS REPORT",
        f"PNCI / Extent of Condition Documentation",
        f"Fiducia - Infrastructure Baseline Management v{settings.APP_VERSION}",
        "=" * 70,
        "",
        f"Report Date:       {check_date.isoformat()}",
        f"Generated:         {datetime.utcnow().isoformat()}",
        f"Generated By:      {current_user.full_name} ({current_user.username})",
        "",
        "-" * 40,
        "SUMMARY",
        "-" * 40,
        f"Total Assets Under Review:    {len(assets)}",
        f"Assets Past Deadline:         {total_overdue}",
        f"Assets Critical (<={thresholds['critical_threshold']} days):   {total_critical}",
        f"Compliance Window:            {thresholds['compliance_window_days']} days",
        "",
    ]

    if recommendations:
        report_lines.extend([
            "-" * 40,
            "RECOMMENDATIONS",
            "-" * 40,
        ])
        for rec in recommendations:
            report_lines.append(f"  * {rec}")
        report_lines.append("")

    report_lines.extend([
        "-" * 40,
        "ASSETS BY TEAM",
        "-" * 40,
        ""
    ])

    for team_id, team_data in sorted(by_team.items(), key=lambda x: x[1]["team_name"]):
        report_lines.append(f"[{team_data['team_name']}]")
        for asset in sorted(team_data["assets"], key=lambda x: x["days_remaining"]):
            status_marker = "OVERDUE" if asset["days_remaining"] < 0 else f"{asset['days_remaining']} days left"
            report_lines.append(f"  - {asset['asset_name']}: {status_marker}")
            if asset["investigation_started"]:
                report_lines.append(f"    Investigation started: {asset['investigation_started'][:10]}")
            report_lines.append(f"    Changes pending: {asset['change_count']}")
        report_lines.append("")

    report_lines.extend([
        "=" * 70,
        "END OF REPORT",
        "=" * 70
    ])

    report_text = "\n".join(report_lines)

    return {
        "report_date": check_date.isoformat(),
        "generated_at": datetime.utcnow().isoformat(),
        "title": "CIP-010 Compliance Status Report",
        "total_assets": len(assets),
        "overdue_count": total_overdue,
        "critical_count": total_critical,
        "assets_by_team": list(by_team.values()),
        "recommendations": recommendations,
        "report_text": report_text
    }


def _flatten_config(config: dict, parent_key: str = '', sep: str = '.') -> list:
    """
    Flatten a nested config dict into field/value pairs.
    Returns list of {"path": "field.path", "value": value}
    """
    items = []
    if not isinstance(config, dict):
        return items

    for key, value in config.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key

        if isinstance(value, dict) and value:
            # Recurse into nested dicts
            items.extend(_flatten_config(value, new_key, sep))
        elif isinstance(value, list):
            # For arrays, show as comma-separated or JSON if complex
            if value and isinstance(value[0], dict):
                # Complex array - show as JSON
                items.append({"path": new_key, "value": json.dumps(value)})
            else:
                # Simple array - join values
                items.append({"path": new_key, "value": ", ".join(str(v) for v in value)})
        else:
            items.append({"path": new_key, "value": str(value) if value is not None else ""})

    return items


@router.get("/compliance/baseline-report")
async def generate_historical_baseline_report(
    report_date: str = Query(..., description="Date in YYYY-MM-DD format"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a comprehensive baseline report for all active assets as of a specific date.

    Returns a text file containing:
    - PNCI/Compliance status section at the top
    - All assets that were active (not retired) on the specified date
    - Their effective baseline with full field values
    """
    from database import BaselineSnapshot

    try:
        check_date = datetime.strptime(report_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    check_datetime = datetime.combine(check_date, datetime.max.time())

    # Get all assets that existed and were not retired as of that date
    assets = db.query(Asset).filter(
        Asset.created_at <= check_datetime,
        or_(
            Asset.retired_at == None,
            Asset.retired_at > check_datetime
        )
    ).order_by(Asset.group_id, Asset.asset_name).all()

    # Get group info
    groups = {g.id: g.name for g in db.query(Group).all()}

    # Get compliance thresholds
    thresholds = get_compliance_thresholds(db)

    # Gather PNCI data - assets in investigation or failed state
    pnci_assets = []
    total_overdue = 0
    total_critical = 0
    total_warning = 0
    total_compliant = 0

    for asset in assets:
        if asset.current_state in [AssetState.INVESTIGATION, AssetState.FAILED]:
            # Get changes for this asset
            changes = db.query(Change).filter(
                Change.asset_id == asset.id,
                Change.status.in_([ChangeStatus.INVESTIGATION, ChangeStatus.PENDING])
            ).all()

            # Find earliest investigation start and due date
            earliest_start = None
            earliest_due_date = None
            for c in changes:
                if c.investigation_started_at:
                    if earliest_start is None or c.investigation_started_at < earliest_start:
                        earliest_start = c.investigation_started_at
                if c.compliance_due_date:
                    if earliest_due_date is None or c.compliance_due_date < earliest_due_date:
                        earliest_due_date = c.compliance_due_date

            # Calculate days remaining
            if earliest_due_date:
                days_remaining = (earliest_due_date - check_date).days
            elif earliest_start:
                due_date = (earliest_start + timedelta(days=thresholds["compliance_window_days"])).date()
                days_remaining = (due_date - check_date).days
            else:
                days_remaining = thresholds["compliance_window_days"]

            # Categorize
            if days_remaining <= 0:
                total_overdue += 1
                status = "OVERDUE"
            elif days_remaining <= thresholds["critical_threshold"]:
                total_critical += 1
                status = "CRITICAL"
            elif days_remaining <= thresholds["yellow_threshold"]:
                total_warning += 1
                status = "WARNING"
            else:
                status = "ON TRACK"

            pnci_assets.append({
                "asset": asset,
                "state": asset.current_state.value if hasattr(asset.current_state, 'value') else str(asset.current_state),
                "days_remaining": days_remaining,
                "status": status,
                "investigation_started": earliest_start,
                "change_count": len(changes),
                "group_name": groups.get(asset.group_id, "Unassigned")
            })
        else:
            total_compliant += 1

    # Build report header with legend
    report_lines = [
        "=" * 100,
        "CIP-010 BASELINE & COMPLIANCE REPORT",
        f"Fiducia - Infrastructure Baseline Management v{settings.APP_VERSION}",
        "=" * 100,
        "",
        f"Report Date:       {check_date.isoformat()}",
        f"Generated:         {datetime.utcnow().isoformat()}",
        f"Generated By:      {current_user.full_name} ({current_user.username})",
        "",
        "-" * 100,
        "REPORT CONTENTS",
        "-" * 100,
        "",
        "  SECTION 1: PNCI / COMPLIANCE STATUS",
        "    - Summary of assets requiring investigation or past compliance deadline",
        "    - Assets grouped by team with days remaining until non-compliance",
        "    - Recommendations for immediate attention items",
        "",
        "  SECTION 2: EFFECTIVE BASELINES",
        "    - Complete baseline configuration for each active asset",
        "    - Field values shown with associated change ticket numbers",
        "    - Assets grouped by team",
        "",
        "-" * 100,
        "SUMMARY",
        "-" * 100,
        f"  Total Active Assets:        {len(assets)}",
        f"  Compliant Assets:           {total_compliant}",
        f"  Under Investigation:        {len(pnci_assets)}",
        f"    - Overdue (past deadline): {total_overdue}",
        f"    - Critical (<={thresholds['critical_threshold']} days):     {total_critical}",
        f"    - Warning (<={thresholds['yellow_threshold']} days):       {total_warning}",
        f"  Compliance Window:          {thresholds['compliance_window_days']} days",
        "",
    ]

    # SECTION 1: PNCI
    report_lines.extend([
        "=" * 100,
        "SECTION 1: PNCI / COMPLIANCE STATUS",
        "=" * 100,
        ""
    ])

    if pnci_assets:
        # Group by team
        pnci_by_team = {}
        for item in pnci_assets:
            team = item["group_name"]
            if team not in pnci_by_team:
                pnci_by_team[team] = []
            pnci_by_team[team].append(item)

        # Recommendations
        recommendations = []
        for item in pnci_assets:
            if item["status"] == "OVERDUE":
                recommendations.append(f"URGENT: {item['asset'].asset_name} is OVERDUE - immediate action required")
            elif item["status"] == "CRITICAL":
                recommendations.append(f"CRITICAL: {item['asset'].asset_name} has {item['days_remaining']} days remaining")

        for team, team_assets in pnci_by_team.items():
            if len(team_assets) >= 3:
                recommendations.append(f"Consider Extent of Condition review for {team} - {len(team_assets)} assets under investigation")

        if recommendations:
            report_lines.append("RECOMMENDATIONS:")
            report_lines.append("")
            for rec in recommendations:
                report_lines.append(f"  * {rec}")
            report_lines.append("")

        report_lines.append("ASSETS REQUIRING ATTENTION:")
        report_lines.append("")

        for team in sorted(pnci_by_team.keys()):
            team_assets = pnci_by_team[team]
            report_lines.append(f"  [{team}] ({len(team_assets)} assets)")
            for item in sorted(team_assets, key=lambda x: x["days_remaining"]):
                if item["days_remaining"] <= 0:
                    status_str = "*** OVERDUE ***"
                else:
                    status_str = f"{item['days_remaining']} days remaining"
                report_lines.append(f"    - {item['asset'].asset_name}: {item['state'].upper()} - {status_str}")
                if item["investigation_started"]:
                    report_lines.append(f"      Investigation started: {item['investigation_started'].strftime('%Y-%m-%d')}")
                report_lines.append(f"      Pending changes: {item['change_count']}")
            report_lines.append("")
    else:
        report_lines.extend([
            "No assets currently under investigation or past compliance deadline.",
            "All assets are in compliant state.",
            ""
        ])

    # SECTION 2: BASELINES
    report_lines.extend([
        "",
        "=" * 100,
        "SECTION 2: EFFECTIVE BASELINES",
        "=" * 100,
        ""
    ])

    current_group = None
    asset_count = 0

    for asset in assets:
        # Group header
        group_name = groups.get(asset.group_id, "Unassigned")
        if group_name != current_group:
            if current_group is not None:
                report_lines.append("")
            report_lines.append("#" * 100)
            report_lines.append(f"GROUP: {group_name}")
            report_lines.append("#" * 100)
            report_lines.append("")
            current_group = group_name

        asset_count += 1

        # Get the baseline that was current as of that date
        baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.promoted_at != None,
            BaselineSnapshot.promoted_at <= check_datetime
        ).order_by(BaselineSnapshot.promoted_at.desc()).first()

        report_lines.append("-" * 100)
        report_lines.append(f"ASSET: {asset.asset_name}")
        report_lines.append("-" * 100)
        report_lines.append(f"  Asset ID:        {asset.id}")
        report_lines.append(f"  FQDN:            {asset.fqdn or 'N/A'}")
        report_lines.append(f"  Team:            {group_name}")

        if baseline:
            report_lines.append(f"  Baseline Date:   {baseline.promoted_at.strftime('%Y-%m-%d %H:%M:%S')}")
            report_lines.append(f"  Baseline Ticket: {baseline.ticket_number or 'None'}")

            # Get field-level tickets
            field_tickets = {}
            if baseline.field_tickets_json:
                try:
                    field_tickets = json.loads(baseline.field_tickets_json)
                except:
                    pass

            # Parse and flatten the config
            try:
                config = json.loads(baseline.config_json)
                flat_config = _flatten_config(config)
            except:
                flat_config = []

            report_lines.append("")
            report_lines.append("  EFFECTIVE BASELINE:")
            report_lines.append("")

            for entry in flat_config:
                field_path = entry["path"]
                value = entry["value"]

                # Get ticket for this field (fall back to baseline ticket)
                ticket = field_tickets.get(field_path, baseline.ticket_number or "")

                # Output full values without truncation for audit purposes
                report_lines.append(f"  [{ticket or 'N/A'}] {field_path}:")
                report_lines.append(f"      {value}")
                report_lines.append("")

            report_lines.append("")
        else:
            report_lines.append("  Baseline:        NO BASELINE FOUND FOR THIS DATE")
            report_lines.append("")

        report_lines.append("")

    report_lines.extend([
        "=" * 100,
        f"END OF REPORT - {asset_count} ASSETS",
        "=" * 100
    ])

    report_text = "\n".join(report_lines)

    # Return as downloadable text file
    filename = f"CIP010_Baseline_Compliance_Report_{check_date.isoformat()}.txt"

    return PlainTextResponse(
        content=report_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )




@router.get("/compliance/custom-baseline-pdf")
async def generate_custom_baseline_pdf(
    report_date: str = Query(..., description="Date in YYYY-MM-DD format"),
    asset_names: str = Query(..., description="Comma-separated list of asset names"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a Baseline and Ticket Research Report for specific assets on a specific date.

    Includes full asset baselines and ticket research showing all authorized changes
    that have shaped the baseline over time for audit documentation.
    """
    from fastapi.responses import Response
    from database import BaselineSnapshot
    
    try:
        check_date = datetime.strptime(report_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    check_datetime = datetime.combine(check_date, datetime.max.time())
    
    # Parse asset names
    requested_names = [name.strip() for name in asset_names.split(",") if name.strip()]
    if not requested_names:
        raise HTTPException(status_code=400, detail="At least one asset name is required")
    
    # Find matching assets (case-insensitive)
    assets = []
    not_found = []
    for name in requested_names:
        asset = db.query(Asset).filter(
            func.lower(Asset.asset_name) == name.lower(),
            Asset.created_at <= check_datetime,
            or_(Asset.retired_at == None, Asset.retired_at > check_datetime)
        ).first()
        if asset:
            assets.append(asset)
        else:
            not_found.append(name)
    
    if not assets:
        raise HTTPException(status_code=404, detail=f"No matching assets found. Not found: {', '.join(not_found)}")
    
    # Get group info
    groups = {g.id: g.name for g in db.query(Group).all()}
    
    # Generate PDF
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        import os
    except ImportError:
        raise HTTPException(status_code=500, detail="PDF generation not available")
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(name="Title", parent=styles["Heading1"], fontSize=16, spaceAfter=6)
    subtitle_style = ParagraphStyle(name="Subtitle", parent=styles["Normal"], fontSize=10, textColor=colors.gray)
    heading_style = ParagraphStyle(name="Heading", parent=styles["Heading2"], fontSize=12, spaceAfter=6, spaceBefore=12)
    
    # Header with logo on right
    logo_path = "/opt/boobytrap/static/fiducia-logo.jpg"
    alt_logo_path = "/home/michael/Fiducia-LZ/static/fiducia-logo.jpg"
    header_content = [
        [Paragraph("Baseline and Ticket Research Report", title_style), ""]
    ]
    
    actual_logo_path = logo_path if os.path.exists(logo_path) else alt_logo_path
    if os.path.exists(actual_logo_path):
        try:
            # Logo is square (960x960), preserve aspect ratio and make it larger
            logo = Image(actual_logo_path, width=1.4*inch, height=1.4*inch)
            header_content[0][1] = logo
        except:
            pass
    
    header_table = Table(header_content, colWidths=[4.5*inch, 2*inch])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
    ]))
    story.append(header_table)
    
    story.append(Paragraph("Full Asset Baselines and Ticket Research for Audit Documentation", subtitle_style))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(f"Report Date: {check_date.isoformat()}", subtitle_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", subtitle_style))
    story.append(Paragraph(f"Generated By: {current_user.full_name} ({current_user.username})", subtitle_style))
    story.append(Paragraph(f"Assets: {len(assets)} found of {len(requested_names)} requested", subtitle_style))
    if not_found:
        story.append(Paragraph(f"Not Found: {', '.join(not_found)}", ParagraphStyle(name="NF", parent=subtitle_style, textColor=colors.red)))
    story.append(Spacer(1, 0.3*inch))
    
    for asset in assets:
        group_name = groups.get(asset.group_id, "Unassigned")
        baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.promoted_at != None,
            BaselineSnapshot.promoted_at <= check_datetime
        ).order_by(BaselineSnapshot.promoted_at.desc()).first()
        
        story.append(Paragraph(f"Asset: {asset.asset_name}", heading_style))
        asset_info = [["FQDN:", asset.fqdn or "N/A"], ["Team:", group_name]]
        if baseline:
            asset_info.append(["Baseline Date:", baseline.promoted_at.strftime("%Y-%m-%d %H:%M")])
            asset_info.append(["Ticket:", baseline.ticket_number or "None"])
        else:
            asset_info.append(["Baseline:", "NO BASELINE FOR DATE"])
        
        info_table = Table(asset_info, colWidths=[1.5*inch, 4*inch])
        info_table.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9), ("TEXTCOLOR", (0, 0), (0, -1), colors.gray)]))
        story.append(info_table)
        story.append(Spacer(1, 0.15*inch))
        
        if baseline:
            field_tickets = {}
            if baseline.field_tickets_json:
                try:
                    field_tickets = json.loads(baseline.field_tickets_json)
                except:
                    pass
            try:
                config = json.loads(baseline.config_json)
                flat_config = _flatten_config(config)
            except:
                flat_config = []
            
            if flat_config:
                # Create paragraph style for wrapping text in cells
                cell_style = ParagraphStyle(name="Cell", fontSize=7, leading=8)
                header_style = ParagraphStyle(name="Header", fontSize=7, leading=8, textColor=colors.white)
                
                baseline_data = [[
                    Paragraph("Field", header_style),
                    Paragraph("Value", header_style),
                    Paragraph("Ticket", header_style)
                ]]
                for entry in flat_config[:50]:  # Limit to 50 fields per asset
                    fp = entry["path"]
                    val = str(entry["value"])
                    tkt = field_tickets.get(fp, baseline.ticket_number or "") or "-"
                    baseline_data.append([
                        Paragraph(fp, cell_style),
                        Paragraph(val, cell_style),
                        Paragraph(tkt, cell_style)
                    ])
                
                baseline_table = Table(baseline_data, colWidths=[1.8*inch, 4*inch, 0.7*inch])
                baseline_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.2, 0.2, 0.3)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.gray),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.Color(0.95, 0.95, 0.95), colors.white]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(baseline_table)
        story.append(Spacer(1, 0.3*inch))

    # ============================================================
    # TICKET RESEARCH SECTION
    # ============================================================
    from reportlab.platypus import PageBreak
    story.append(PageBreak())

    ticket_section_style = ParagraphStyle(
        name="TicketSection",
        parent=styles["Heading1"],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=6,
        textColor=colors.Color(0.1, 0.3, 0.5)
    )
    ticket_note_style = ParagraphStyle(
        name="TicketNote",
        parent=styles["Normal"],
        fontSize=9,
        textColor=colors.Color(0.3, 0.3, 0.3),
        spaceAfter=12,
        leading=12
    )

    story.append(Paragraph("Ticket Research Documentation", ticket_section_style))
    story.append(Paragraph(
        "The tickets listed below, in sequential order, represent the authorized changes to each asset over time. "
        "Each ticket documents a baseline modification that has been reviewed and approved through the change management process. "
        "This audit trail demonstrates compliance with CIP-010 requirements for configuration change authorization.",
        ticket_note_style
    ))
    story.append(Spacer(1, 0.2*inch))

    # Query audit logs for ticket history for each asset
    for asset in assets:
        # Collect all tickets for this asset from multiple sources
        ticket_history = []

        # 1. Initial baseline ticket
        initial_baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.promoted_at != None,
            BaselineSnapshot.promoted_at <= check_datetime
        ).order_by(BaselineSnapshot.promoted_at.asc()).first()

        if initial_baseline and initial_baseline.ticket_number:
            ticket_history.append({
                "date": initial_baseline.promoted_at,
                "ticket": initial_baseline.ticket_number,
                "action": "Initial Baseline Established",
                "user": initial_baseline.promoted_by or "System"
            })

        # 2. Query finalization audit logs for this asset's changes
        finalization_logs = db.query(AuditLog).filter(
            AuditLog.action == "finalize_baselines",
            AuditLog.timestamp <= check_datetime
        ).order_by(AuditLog.timestamp.asc()).all()

        for log in finalization_logs:
            if log.details_json:
                try:
                    details = json.loads(log.details_json)
                    for asset_data in details.get("finalized_assets", []):
                        if asset_data.get("name") == asset.asset_name or asset_data.get("id") == asset.id:
                            for change in asset_data.get("changes", []):
                                ticket = change.get("ticket_number")
                                if ticket:
                                    # Check if we already have this ticket+date combo
                                    existing = next((t for t in ticket_history
                                                    if t["ticket"] == ticket and t["date"].date() == log.timestamp.date()), None)
                                    if not existing:
                                        ticket_history.append({
                                            "date": log.timestamp,
                                            "ticket": ticket,
                                            "action": f"Change Approved: {change.get('field_path', 'configuration')}",
                                            "user": change.get("approved_by") or log.user_id or "System"
                                        })
                except json.JSONDecodeError:
                    pass

        # 3. Get all unique tickets from field_tickets_json across all baselines
        all_baselines = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.promoted_at != None,
            BaselineSnapshot.promoted_at <= check_datetime
        ).order_by(BaselineSnapshot.promoted_at.asc()).all()

        for bl in all_baselines:
            if bl.field_tickets_json:
                try:
                    field_tickets = json.loads(bl.field_tickets_json)
                    for field_path, ticket in field_tickets.items():
                        if ticket:
                            existing = next((t for t in ticket_history if t["ticket"] == ticket), None)
                            if not existing:
                                ticket_history.append({
                                    "date": bl.promoted_at,
                                    "ticket": ticket,
                                    "action": f"Field Change: {field_path}",
                                    "user": bl.promoted_by or "System"
                                })
                except json.JSONDecodeError:
                    pass

        # Sort by date and deduplicate by ticket number (keep first occurrence)
        ticket_history.sort(key=lambda x: x["date"])
        seen_tickets = set()
        unique_tickets = []
        for entry in ticket_history:
            if entry["ticket"] not in seen_tickets:
                seen_tickets.add(entry["ticket"])
                unique_tickets.append(entry)

        # Render ticket history for this asset
        asset_heading = ParagraphStyle(
            name="AssetTicketHeading",
            parent=styles["Heading3"],
            fontSize=11,
            spaceAfter=6,
            spaceBefore=12,
            textColor=colors.Color(0.2, 0.2, 0.4)
        )
        story.append(Paragraph(f"Asset: {asset.asset_name}", asset_heading))

        if unique_tickets:
            ticket_cell_style = ParagraphStyle(name="TicketCell", fontSize=8, leading=10)
            ticket_header_style = ParagraphStyle(name="TicketHeader", fontSize=8, leading=10, textColor=colors.white)

            ticket_table_data = [[
                Paragraph("#", ticket_header_style),
                Paragraph("Date", ticket_header_style),
                Paragraph("Ticket Number", ticket_header_style),
                Paragraph("Action", ticket_header_style),
                Paragraph("User", ticket_header_style)
            ]]

            for idx, entry in enumerate(unique_tickets, 1):
                ticket_table_data.append([
                    Paragraph(str(idx), ticket_cell_style),
                    Paragraph(entry["date"].strftime("%Y-%m-%d"), ticket_cell_style),
                    Paragraph(entry["ticket"], ticket_cell_style),
                    Paragraph(entry["action"][:50] + "..." if len(entry["action"]) > 50 else entry["action"], ticket_cell_style),
                    Paragraph(str(entry["user"]), ticket_cell_style)
                ])

            ticket_table = Table(ticket_table_data, colWidths=[0.3*inch, 0.8*inch, 1.2*inch, 2.5*inch, 1.5*inch])
            ticket_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.15, 0.35, 0.55)),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.Color(0.7, 0.7, 0.7)),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.Color(0.95, 0.97, 1.0)]),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(ticket_table)
            story.append(Spacer(1, 0.1*inch))

            ticket_count_style = ParagraphStyle(name="TicketCount", fontSize=8, textColor=colors.gray)
            story.append(Paragraph(f"Total authorized changes documented: {len(unique_tickets)} ticket(s)", ticket_count_style))
        else:
            no_ticket_style = ParagraphStyle(name="NoTicket", fontSize=9, textColor=colors.gray, fontName="Helvetica-Oblique")
            story.append(Paragraph("No ticket history available for this asset.", no_ticket_style))

        story.append(Spacer(1, 0.2*inch))

    # Footer
    story.append(Spacer(1, 0.3*inch))
    footer_style = ParagraphStyle(name="Footer", fontSize=8, textColor=colors.gray, alignment=1)  # 1 = center
    story.append(Paragraph("--- End of Baseline and Ticket Research Report ---", footer_style))

    doc.build(story)
    buffer.seek(0)
    filename = f"Baseline_Ticket_Research_{check_date.isoformat()}.pdf"

    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )



@router.get("/compliance/investigation-report")
async def generate_investigation_report(
    report_date: str = Query(..., description="Date in YYYY-MM-DD format"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a detailed investigation report for all assets in investigation state.

    Shows for each investigation:
    - Asset details
    - When investigation started (Day 1)
    - Days elapsed since investigation started
    - All changes under investigation with full details
    - Compliance deadline and days remaining

    Also includes CLOSED investigations for the report date with:
    - Closure details (who, when, ticket numbers)
    - Promoted baseline changes
    """
    from database import BaselineSnapshot

    try:
        check_date = datetime.strptime(report_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    check_datetime_start = datetime.combine(check_date, datetime.min.time())
    check_datetime_end = datetime.combine(check_date, datetime.max.time())
    today = date.today()
    is_historical = check_date < today

    # Get compliance thresholds
    thresholds = get_compliance_thresholds(db)

    # Get group info
    groups = {g.id: g.name for g in db.query(Group).all()}

    # ============================================================
    # OPEN INVESTIGATIONS (still active on the report date)
    # ============================================================
    if is_historical:
        # Historical: find changes that were in investigation on that date
        open_investigations = db.query(Change, Asset).join(Asset).filter(
            Change.investigation_started_at != None,
            Change.investigation_started_at <= check_datetime_end,
            or_(
                Change.status == ChangeStatus.INVESTIGATION,
                Change.status_changed_at > check_datetime_end
            )
        ).all()
    else:
        # Current: find all active investigations
        open_investigations = db.query(Change, Asset).join(Asset).filter(
            Change.status == ChangeStatus.INVESTIGATION
        ).all()

    # ============================================================
    # CLOSED INVESTIGATIONS (resolved on the report date)
    # ============================================================
    # Since changes are deleted after finalization, we query audit logs
    # for investigation closures (change_approved/change_rejected with "from investigation")

    # First, try the changes table (for same-day before deletion)
    closed_from_changes = db.query(Change, Asset).join(Asset).filter(
        Change.investigation_started_at != None,
        Change.status.in_([ChangeStatus.APPROVED, ChangeStatus.REJECTED]),
        Change.status_changed_at >= check_datetime_start,
        Change.status_changed_at <= check_datetime_end
    ).all()

    # Also query audit logs for investigation approvals/rejections
    # These capture investigation closures even after changes are deleted
    investigation_closure_logs = db.query(AuditLog).filter(
        AuditLog.action.in_(["change_approved", "change_rejected"]),
        AuditLog.action_detail.like("%from investigation%"),
        AuditLog.timestamp >= check_datetime_start,
        AuditLog.timestamp <= check_datetime_end
    ).all()

    # Get the finalization logs to match with ticket numbers and change details
    finalization_logs = db.query(AuditLog).filter(
        AuditLog.action == "finalize_baselines",
        AuditLog.timestamp >= check_datetime_start,
        AuditLog.timestamp <= check_datetime_end
    ).all()

    # Parse finalization logs to get asset details with tickets
    finalized_asset_details = {}
    for log in finalization_logs:
        if log.details_json:
            try:
                details = json.loads(log.details_json)
                for asset_data in details.get("finalized_assets", []):
                    asset_name = asset_data.get("name")
                    if asset_name not in finalized_asset_details:
                        finalized_asset_details[asset_name] = {
                            "finalized_at": log.timestamp,
                            "changes": []
                        }
                    finalized_asset_details[asset_name]["changes"].extend(asset_data.get("changes", []))
            except json.JSONDecodeError:
                pass

    # Build closed investigations from audit logs
    closed_investigations = []
    closed_asset_ids = set()

    for audit_log in investigation_closure_logs:
        asset_id = audit_log.asset_id
        if asset_id and asset_id not in closed_asset_ids:
            asset = db.query(Asset).filter(Asset.id == asset_id).first()
            if asset:
                closed_asset_ids.add(asset_id)
                # Find the investigation start time from bulk_investigation logs
                inv_start_log = db.query(AuditLog).filter(
                    AuditLog.action == "bulk_investigation",
                    AuditLog.details_json.like(f'%"id": {asset_id}%'),
                    AuditLog.timestamp <= audit_log.timestamp
                ).order_by(AuditLog.timestamp.desc()).first()

                inv_started_at = inv_start_log.timestamp if inv_start_log else None

                # Get change details from finalization log
                asset_finalized = finalized_asset_details.get(asset.asset_name, {})

                closed_investigations.append({
                    "asset": asset,
                    "investigation_started_at": inv_started_at,
                    "closed_at": audit_log.timestamp,
                    "changes": asset_finalized.get("changes", [])
                })

    # Group OPEN investigations by asset
    open_asset_investigations = {}
    for change, asset in open_investigations:
        if asset.id not in open_asset_investigations:
            baseline = db.query(BaselineSnapshot).filter(
                BaselineSnapshot.asset_id == asset.id,
                BaselineSnapshot.is_current_baseline == True
            ).first()

            open_asset_investigations[asset.id] = {
                "asset": asset,
                "baseline": baseline,
                "changes": [],
                "earliest_investigation_start": None
            }

        open_asset_investigations[asset.id]["changes"].append(change)

        if change.investigation_started_at:
            current_earliest = open_asset_investigations[asset.id]["earliest_investigation_start"]
            if current_earliest is None or change.investigation_started_at < current_earliest:
                open_asset_investigations[asset.id]["earliest_investigation_start"] = change.investigation_started_at

    # Build closed_asset_investigations from the audit-log-based closed_investigations list
    closed_asset_investigations = {}
    for inv_data in closed_investigations:
        asset = inv_data["asset"]
        if asset.id not in closed_asset_investigations:
            closed_asset_investigations[asset.id] = {
                "asset": asset,
                "changes": inv_data["changes"],
                "earliest_investigation_start": inv_data["investigation_started_at"],
                "closure_time": inv_data["closed_at"],
                "closed_by": None  # Could be retrieved from audit log if needed
            }

    total_investigations = len(open_asset_investigations) + len(closed_asset_investigations)

    # Build report
    report_lines = [
        "=" * 80,
        "INVESTIGATION STATUS REPORT",
        f"Fiducia - Infrastructure Baseline Management v{settings.APP_VERSION}",
        "=" * 80,
        "",
        f"Report Date:       {check_date.isoformat()}" + (" (HISTORICAL)" if is_historical else " (CURRENT)"),
        f"Generated:         {datetime.utcnow().isoformat()}",
        f"Generated By:      {current_user.full_name} ({current_user.username})",
        f"Compliance Window: {thresholds['compliance_window_days']} days",
        "",
        f"Total Investigations: {total_investigations}",
        f"  Open:   {len(open_asset_investigations)}",
        f"  Closed: {len(closed_asset_investigations)}",
        "",
        "=" * 80,
        ""
    ]

    # ============================================================
    # OPEN INVESTIGATIONS SECTION
    # ============================================================
    if open_asset_investigations:
        report_lines.extend([
            "#" * 80,
            "OPEN INVESTIGATIONS",
            "#" * 80,
            ""
        ])

        summary = {"on_track": 0, "warning": 0, "critical": 0, "overdue": 0}

        for asset_id, data in sorted(open_asset_investigations.items(), key=lambda x: x[1]["asset"].asset_name):
            asset = data["asset"]
            changes = data["changes"]
            investigation_start = data["earliest_investigation_start"]

            if investigation_start:
                days_in_investigation = (check_date - investigation_start.date()).days
                due_date = (investigation_start + timedelta(days=thresholds["compliance_window_days"])).date()
                days_remaining = (due_date - check_date).days
            else:
                days_in_investigation = 0
                days_remaining = thresholds["compliance_window_days"]
                due_date = None

            status = determine_status(days_remaining, thresholds)
            summary[status] += 1

            status_text = {
                "on_track": "ON TRACK",
                "warning": "WARNING",
                "critical": "CRITICAL",
                "overdue": "OVERDUE - NON-COMPLIANT"
            }.get(status, status.upper())

            group_name = groups.get(asset.group_id, "Unassigned")

            report_lines.extend([
                "-" * 80,
                f"ASSET: {asset.asset_name}",
                "-" * 80,
                f"  Asset ID:              {asset.id}",
                f"  FQDN:                  {asset.fqdn or 'N/A'}",
                f"  Team:                  {group_name}",
                f"  Current State:         {asset.current_state.value if hasattr(asset.current_state, 'value') else str(asset.current_state)}",
                "",
                f"  INVESTIGATION TIMELINE:",
                f"    Day 1 (Started):     {investigation_start.strftime('%Y-%m-%d %H:%M:%S') if investigation_start else 'Unknown'}",
                f"    Days Elapsed:        {days_in_investigation} days",
                f"    Compliance Due:      {due_date.isoformat() if due_date else 'Not Set'}",
                f"    Days Remaining:      {days_remaining} days",
                f"    Status:              {status_text}",
                "",
                f"  CHANGES UNDER INVESTIGATION ({len(changes)}):",
            ])

            for i, change in enumerate(changes, 1):
                report_lines.append(f"    [{i}] Field: {change.field_path}")
                report_lines.append(f"        Type: {change.change_type}")
                report_lines.append(f"        Detected: {change.detected_at.strftime('%Y-%m-%d %H:%M:%S') if change.detected_at else 'Unknown'}")

                if change.old_value:
                    try:
                        old_val = json.loads(change.old_value)
                        old_str = json.dumps(old_val, indent=8) if isinstance(old_val, (dict, list)) else str(old_val)
                    except:
                        old_str = str(change.old_value)
                    if len(old_str) > 200:
                        old_str = old_str[:200] + "..."
                    report_lines.append(f"        Old Value: {old_str}")

                if change.new_value:
                    try:
                        new_val = json.loads(change.new_value)
                        new_str = json.dumps(new_val, indent=8) if isinstance(new_val, (dict, list)) else str(new_val)
                    except:
                        new_str = str(change.new_value)
                    if len(new_str) > 200:
                        new_str = new_str[:200] + "..."
                    report_lines.append(f"        New Value: {new_str}")

                report_lines.append("")

            report_lines.append("")

        # Open investigations summary
        report_lines.extend([
            "-" * 40,
            "OPEN INVESTIGATIONS SUMMARY",
            "-" * 40,
            f"  Total Open:            {len(open_asset_investigations)}",
            f"  On Track:              {summary['on_track']}",
            f"  Warning:               {summary['warning']}",
            f"  Critical:              {summary['critical']}",
            f"  Overdue:               {summary['overdue']}",
            ""
        ])

        if summary['overdue'] > 0:
            report_lines.extend([
                "  ⚠️  COMPLIANCE ACTION REQUIRED",
                f"  {summary['overdue']} asset(s) have exceeded the {thresholds['compliance_window_days']}-day",
                "  compliance window and require PNCI documentation.",
                ""
            ])

    else:
        report_lines.extend([
            "#" * 80,
            "OPEN INVESTIGATIONS",
            "#" * 80,
            "",
            "No open investigations on this date.",
            ""
        ])

    # ============================================================
    # CLOSED INVESTIGATIONS SECTION
    # ============================================================
    if closed_asset_investigations:
        report_lines.extend([
            "",
            "#" * 80,
            "CLOSED INVESTIGATIONS",
            "#" * 80,
            "",
            "The following investigations were closed on this date.",
            "Assets have been restored to baseline compliance.",
            ""
        ])

        for asset_id, data in sorted(closed_asset_investigations.items(), key=lambda x: x[1]["asset"].asset_name):
            asset = data["asset"]
            changes = data["changes"]  # List of dicts from audit log
            investigation_start = data["earliest_investigation_start"]
            closure_time = data["closure_time"]
            closed_by = data["closed_by"]

            # Calculate investigation duration
            if investigation_start and closure_time:
                investigation_duration = (closure_time.date() - investigation_start.date()).days
            else:
                investigation_duration = 0

            group_name = groups.get(asset.group_id, "Unassigned")

            # Collect unique ticket numbers (changes are dicts now)
            ticket_numbers = set()
            for change in changes:
                ticket = change.get("ticket_number")
                if ticket:
                    ticket_numbers.add(ticket)
            tickets_str = ", ".join(sorted(ticket_numbers)) if ticket_numbers else "None specified"

            # All changes from finalization are approved (promoted to baseline)
            approved_count = len(changes)
            rejected_count = 0

            report_lines.extend([
                "-" * 80,
                f"ASSET: {asset.asset_name} [INVESTIGATION CLOSED]",
                "-" * 80,
                f"  Asset ID:              {asset.id}",
                f"  FQDN:                  {asset.fqdn or 'N/A'}",
                f"  Team:                  {group_name}",
                f"  Current State:         {asset.current_state.value if hasattr(asset.current_state, 'value') else str(asset.current_state)}",
                "",
                f"  CLOSURE DETAILS:",
                f"    Investigation Start: {investigation_start.strftime('%Y-%m-%d %H:%M:%S') if investigation_start else 'Unknown'}",
                f"    Closed At:           {closure_time.strftime('%Y-%m-%d %H:%M:%S') if closure_time else 'Unknown'}",
                f"    Closed By:           {closed_by or 'Unknown'}",
                f"    Duration:            {investigation_duration} day(s)",
                f"    Ticket Number(s):    {tickets_str}",
                "",
                f"  RESOLUTION SUMMARY:",
                f"    Changes Approved:    {approved_count} (promoted to baseline)",
                f"    Changes Rejected:    {rejected_count} (not promoted)",
                "",
                f"  CHANGES RESOLVED ({len(changes)}):",
            ])

            for i, change in enumerate(changes, 1):
                # Changes are dicts from audit log
                ticket_label = f" [Ticket: {change.get('ticket_number')}]" if change.get('ticket_number') else ""

                report_lines.append(f"    [{i}] APPROVED{ticket_label}")
                report_lines.append(f"        Field: {change.get('field', 'Unknown')}")
                report_lines.append(f"        Type: {change.get('change_type', 'Unknown')}")

                old_value = change.get('old_value')
                if old_value is not None:
                    old_str = str(old_value)
                    if len(old_str) > 200:
                        old_str = old_str[:200] + "..."
                    report_lines.append(f"        Previous Baseline: {old_str}")

                new_value = change.get('new_value')
                if new_value is not None:
                    new_str = str(new_value)
                    if len(new_str) > 200:
                        new_str = new_str[:200] + "..."
                    report_lines.append(f"        PROMOTED TO BASELINE: {new_str}")

                report_lines.append("")

            report_lines.append("")

        # Closed investigations summary
        total_changes = sum(len(data["changes"]) for data in closed_asset_investigations.values())

        report_lines.extend([
            "-" * 40,
            "CLOSED INVESTIGATIONS SUMMARY",
            "-" * 40,
            f"  Investigations Closed: {len(closed_asset_investigations)}",
            f"  Total Changes:         {total_changes}",
            ""
        ])

    else:
        report_lines.extend([
            "",
            "#" * 80,
            "CLOSED INVESTIGATIONS",
            "#" * 80,
            "",
            "No investigations were closed on this date.",
            ""
        ])

    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    report_lines.extend([
        "",
        "=" * 80,
        "REPORT SUMMARY",
        "=" * 80,
        f"  Report Date:           {check_date.isoformat()}",
        f"  Open Investigations:   {len(open_asset_investigations)}",
        f"  Closed Investigations: {len(closed_asset_investigations)}",
        "",
        "=" * 80,
        "END OF REPORT",
        "=" * 80
    ])

    report_text = "\n".join(report_lines)

    # Return as downloadable text file
    filename = f"Investigation_Report_{check_date.isoformat()}.txt"

    return PlainTextResponse(
        content=report_text,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================
# REPORTS
# ============================================================

@router.get("", response_model=list[ReportResponse])
async def list_reports(
    report_type: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all reports with optional filtering."""
    query = db.query(Report)

    if report_type:
        query = query.filter(Report.report_type == report_type)

    reports = query.order_by(Report.generated_at.desc()).limit(limit).all()
    return reports


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific report by ID."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download report as plain text file."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    filename = f"CIP010_report_{report.id}_{report.generated_at.strftime('%Y%m%d_%H%M%S')}.txt"

    return PlainTextResponse(
        content=report.report_content,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================
# INVESTIGATION CLOSURE REPORTS
# ============================================================

@router.get("/investigation-closures/list")
async def list_investigation_closures(
    filter_date: Optional[str] = Query(None, description="Filter by date (YYYY-MM-DD)"),
    search: Optional[str] = Query(None, description="Search term"),
    search_type: Optional[str] = Query("asset", description="Search type: asset or ticket"),
    limit: int = Query(50, description="Max results to return"),
    offset: int = Query(0, description="Results offset for pagination"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List investigation closures from audit logs with optional filtering.
    """
    date_filter = None
    if filter_date:
        try:
            filter_dt = datetime.strptime(filter_date, "%Y-%m-%d").date()
            date_filter = filter_dt
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")

    query = db.query(AuditLog).filter(
        AuditLog.action == "finalize_baselines",
        AuditLog.action_detail.like("%investigation%")
    )

    if date_filter:
        query = query.filter(func.date(AuditLog.timestamp) == date_filter)

    finalization_logs = query.order_by(AuditLog.timestamp.desc()).all()
    closures = []
    search_lower = search.lower() if search else None

    for log in finalization_logs:
        if not log.details_json:
            continue
        try:
            details = json.loads(log.details_json)
            investigations_closed = details.get("investigations_closed", [])
            if not investigations_closed:
                continue

            closed_by_username = None
            if log.user_id:
                user = db.query(User).filter(User.id == log.user_id).first()
                if user:
                    closed_by_username = user.username

            for inv in investigations_closed:
                if search_lower:
                    if search_type == "asset":
                        asset_name = inv.get("name", "").lower()
                        if search_lower not in asset_name:
                            continue
                    elif search_type == "ticket":
                        change_details = inv.get("changes", [])
                        ticket_found = False
                        for change in change_details:
                            ticket = change.get("ticket_number", "")
                            if ticket and search_lower in ticket.lower():
                                ticket_found = True
                                break
                        if not ticket_found:
                            continue

                closure_entry = {
                    "audit_log_id": log.id,
                    "closure_date": log.timestamp.isoformat(),
                    "closure_date_display": log.timestamp.strftime("%Y-%m-%d %H:%M"),
                    "closed_by": log.user_id,
                    "closed_by_username": closed_by_username,
                    "asset_id": inv.get("id"),
                    "asset_name": inv.get("name"),
                    "asset_fqdn": inv.get("fqdn"),
                    "group": inv.get("group"),
                    "changes_count": inv.get("changes_finalized", 0),
                    "investigation_started_at": inv.get("investigation_started_at"),
                    "investigation_duration_days": inv.get("investigation_duration_days"),
                    "has_notes": bool(inv.get("investigation_notes")),
                    "ticket_numbers": list(set(c.get("ticket_number") for c in inv.get("changes", []) if c.get("ticket_number")))
                }
                closures.append(closure_entry)
        except json.JSONDecodeError:
            continue

    total_closures = len(closures)
    paginated_closures = closures[offset:offset + limit]

    closures_by_date = {}
    for closure in paginated_closures:
        date_key = closure["closure_date"][:10]
        if date_key not in closures_by_date:
            closures_by_date[date_key] = []
        closures_by_date[date_key].append(closure)

    return {
        "total_closures": total_closures,
        "showing": len(paginated_closures),
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total_closures,
        "filter_date": filter_date,
        "search": search,
        "search_type": search_type,
        "closures": paginated_closures,
        "closures_by_date": closures_by_date
    }




@router.get("/investigation-closure-pdf/{audit_log_id}")
async def generate_investigation_closure_pdf(
    audit_log_id: int,
    asset_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a PDF report for a specific investigation closure.

    If asset_id is provided, generates PDF for just that asset.
    Otherwise generates a PDF for all investigation closures in that audit log entry.
    """
    from fastapi.responses import Response
    import io

    # Get the audit log entry
    audit_log = db.query(AuditLog).filter(AuditLog.id == audit_log_id).first()
    if not audit_log:
        raise HTTPException(status_code=404, detail="Audit log not found")

    if audit_log.action != "finalize_baselines":
        raise HTTPException(status_code=400, detail="Not an investigation closure audit log")

    try:
        details = json.loads(audit_log.details_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid audit log data")

    investigations_closed = details.get("investigations_closed", [])
    if not investigations_closed:
        raise HTTPException(status_code=404, detail="No investigation closures in this audit log")

    # Filter to specific asset if requested
    if asset_id:
        investigations_closed = [inv for inv in investigations_closed if inv.get("id") == asset_id]
        if not investigations_closed:
            raise HTTPException(status_code=404, detail="Asset not found in this closure")

    # Get user info
    closed_by_username = "Unknown"
    if audit_log.user_id:
        user = db.query(User).filter(User.id == audit_log.user_id).first()
        if user:
            closed_by_username = user.username

    # Generate the PDF
    pdf_buffer = _generate_investigation_closure_pdf(
        investigations_closed=investigations_closed,
        closure_time=audit_log.timestamp,
        closed_by=closed_by_username
    )

    # Create filename
    if asset_id and len(investigations_closed) == 1:
        asset_name = investigations_closed[0].get("name", "asset").replace(" ", "_")
        filename = f"Investigation_Closure_{asset_name}_{audit_log.timestamp.strftime('%Y%m%d')}.pdf"
    else:
        filename = f"Investigation_Closure_Report_{audit_log.timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"

    return Response(
        content=pdf_buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def _generate_investigation_closure_pdf(investigations_closed: list, closure_time: datetime, closed_by: str) -> io.BytesIO:
    """
    Generate a PDF report for investigation closures.
    Clean, structured layout without overlapping text.
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import io
    import os

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch,
                           leftMargin=0.6*inch, rightMargin=0.6*inch)

    styles = getSampleStyleSheet()

    # Clean styles without problematic backColor on paragraphs
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=6,
                                  alignment=TA_CENTER, textColor=colors.HexColor('#92400e'))
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10,
                                     alignment=TA_CENTER, textColor=colors.HexColor('#6b7280'),
                                     spaceAfter=4)
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=12,
                                    spaceBefore=16, spaceAfter=8, textColor=colors.HexColor('#92400e'),
                                    fontName='Helvetica-Bold')
    normal_style = ParagraphStyle('CustomNormal', parent=styles['Normal'], fontSize=9, spaceAfter=6,
                                   leading=12)

    story = []

    # Logo
    logo_paths = [
        "/home/michael/Fiducia-LZ/static/fiducia-logo.jpg",
        "/opt/boobytrap/static/img/fiducia_logo.png",
        "static/fiducia-logo.jpg"
    ]
    for logo_path in logo_paths:
        if os.path.exists(logo_path):
            try:
                img = Image(logo_path, width=1.2*inch, height=1.2*inch)
                img.hAlign = 'CENTER'
                story.append(img)
                story.append(Spacer(1, 0.15*inch))
                break
            except:
                pass

    # Title
    story.append(Paragraph("INVESTIGATION CLOSURE REPORT", title_style))
    story.append(Paragraph(f"Generated: {closure_time.strftime('%Y-%m-%d %H:%M:%S')} UTC", subtitle_style))
    story.append(Paragraph(f"Fiducia v{settings.APP_VERSION} - CIP-010 Compliance Documentation", subtitle_style))
    story.append(Spacer(1, 0.25*inch))

    # Summary Table
    total_changes = sum(inv.get("changes_finalized", 0) for inv in investigations_closed)
    all_tickets = set()
    for inv in investigations_closed:
        for change in inv.get("changes", []):
            if change.get("ticket_number"):
                all_tickets.add(change["ticket_number"])

    summary_data = [
        ["Closed By:", closed_by],
        ["Investigations Closed:", str(len(investigations_closed))],
        ["Total Changes Resolved:", str(total_changes)],
    ]
    if all_tickets:
        summary_data.append(["Related Tickets:", ", ".join(sorted(all_tickets))])

    summary_table = Table(summary_data, colWidths=[1.8*inch, 5*inch])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef3c7')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#d97706')),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#fcd34d')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    # Per-investigation details
    for idx, inv in enumerate(investigations_closed, 1):
        if idx > 1:
            story.append(Spacer(1, 0.3*inch))

        # Investigation header
        story.append(Paragraph(f"Investigation {idx}: {inv.get('name', 'Unknown')}", section_style))

        # Asset & Timeline info table
        info_data = []
        if inv.get('fqdn'):
            info_data.append(["FQDN:", inv['fqdn']])
        if inv.get('group'):
            info_data.append(["Team:", inv['group']])
        info_data.append(["Changes Resolved:", str(inv.get('changes_finalized', 0))])

        if inv.get("investigation_started_at"):
            try:
                start_dt = datetime.fromisoformat(inv["investigation_started_at"].replace('Z', '+00:00'))
                info_data.append(["Investigation Opened:", start_dt.strftime("%Y-%m-%d %H:%M:%S UTC")])
            except:
                info_data.append(["Investigation Opened:", str(inv["investigation_started_at"])])

        info_data.append(["Investigation Closed:", closure_time.strftime("%Y-%m-%d %H:%M:%S UTC")])

        if inv.get("investigation_duration_days") is not None:
            duration = inv["investigation_duration_days"]
            duration_str = "Same day" if duration == 0 else f"{duration} day{'s' if duration != 1 else ''}"
            info_data.append(["Duration:", duration_str])
            compliance_str = "WITHIN 35-DAY WINDOW" if duration <= 35 else f"EXCEEDED BY {duration - 35} DAYS"
            info_data.append(["Compliance:", compliance_str])

        if info_data:
            info_table = Table(info_data, colWidths=[1.8*inch, 5*inch])
            info_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(info_table)

        # Investigation Notes
        if inv.get("investigation_notes"):
            story.append(Spacer(1, 0.1*inch))
            notes_table = Table([["Investigation Notes:", inv["investigation_notes"]]], colWidths=[1.8*inch, 5*inch])
            notes_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, 0), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.HexColor('#6b7280')),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef9e7')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#fcd34d')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(notes_table)

        story.append(Spacer(1, 0.15*inch))

        # Changes section header
        changes = inv.get('changes', [])
        if changes:
            story.append(Paragraph(f"Changes Resolved ({len(changes)}):", normal_style))
            story.append(Spacer(1, 0.1*inch))

            for i, change in enumerate(changes, 1):
                field_name = change.get('field', 'Unknown Field')
                change_type = change.get('change_type', 'modified').upper().replace('_', ' ')

                # Build change data rows
                change_rows = [
                    ["Field:", field_name],
                    ["Type:", change_type],
                ]

                # Handle values based on change type
                if change.get('change_type', '').lower() == 'array_modified':
                    items_added = change.get('items_added') or []
                    items_removed = change.get('items_removed') or []

                    if items_removed:
                        removed_str = "\n".join([f"  - {item}" if not isinstance(item, dict) else f"  - {{{', '.join(f'{k}: {v}' for k, v in item.items())}}}" for item in items_removed])
                        change_rows.append([f"Removed ({len(items_removed)}):", removed_str])

                    if items_added:
                        added_str = "\n".join([f"  + {item}" if not isinstance(item, dict) else f"  + {{{', '.join(f'{k}: {v}' for k, v in item.items())}}}" for item in items_added])
                        change_rows.append([f"Added ({len(items_added)}):", added_str])
                else:
                    old_val = change.get('old_value')
                    new_val = change.get('new_value')

                    if old_val is not None:
                        if isinstance(old_val, (dict, list)):
                            old_str = json.dumps(old_val, indent=2)
                        else:
                            old_str = str(old_val)
                        change_rows.append(["Before:", old_str])

                    if new_val is not None:
                        if isinstance(new_val, (dict, list)):
                            new_str = json.dumps(new_val, indent=2)
                        else:
                            new_str = str(new_val)
                        change_rows.append(["After:", new_str])

                # Metadata
                if change.get('ticket_number'):
                    change_rows.append(["Ticket #:", change['ticket_number']])
                if change.get('approved_by'):
                    change_rows.append(["Approved By:", change['approved_by']])
                if change.get('approved_at'):
                    change_rows.append(["Approved At:", str(change['approved_at'])])
                if change.get('time_to_close_days') is not None:
                    days = change['time_to_close_days']
                    change_rows.append(["Time to Close:", "Same day" if days == 0 else f"{days} day{'s' if days != 1 else ''}"])
                if change.get('resolution_notes'):
                    change_rows.append(["Notes:", change['resolution_notes']])

                # Create change table
                change_table = Table(change_rows, colWidths=[1.3*inch, 5.5*inch])
                change_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fafb')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db')),
                    ('LINEBELOW', (0, 0), (-1, -2), 0.25, colors.HexColor('#e5e7eb')),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ]))

                story.append(Paragraph(f"<b>Change {i}:</b>", normal_style))
                story.append(change_table)
                story.append(Spacer(1, 0.15*inch))

    # Footer
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("— End of Investigation Closure Report —", subtitle_style))
    story.append(Paragraph(f"Fiducia v{settings.APP_VERSION} • CIP-010 Baseline Management", subtitle_style))

    doc.build(story)
    buffer.seek(0)
    return buffer


@router.get("/ticket-search-pdf/{ticket_number}")
async def generate_ticket_search_pdf(
    ticket_number: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate a PDF report for all changes associated with a ticket number."""
    from api.routes.changes import _safe_json_loads
    from database.models import Change, ChangeStatus, Asset, Group as GroupModel

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
                        asset_name = asset_data.get("name")
                        if asset_name not in results_by_asset:
                            results_by_asset[asset_name] = {
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
                            "status": "approved",
                            "approved_by": change.get("approved_by"),
                            "approved_at": change.get("approved_at"),
                            "finalized_at": log.timestamp.isoformat(),
                            "resolution_notes": change.get("resolution_notes")
                        })
        except json.JSONDecodeError:
            continue

    pending_changes = db.query(Change).filter(Change.ticket_number == ticket_number).all()

    for change in pending_changes:
        asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
        if not asset:
            continue
        asset_name = asset.asset_name
        if asset_name not in results_by_asset:
            group = db.query(GroupModel).filter(GroupModel.id == asset.group_id).first()
            results_by_asset[asset_name] = {
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

    if not results_by_asset:
        raise HTTPException(status_code=404, detail=f"No changes found for ticket {ticket_number}")

    pdf_buffer = _generate_ticket_search_pdf(ticket_number, results_by_asset)
    safe_ticket = ticket_number.replace("/", "-").replace(" ", "_")
    filename = f"ticket_report_{safe_ticket}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


def _generate_ticket_search_pdf(ticket_number: str, results_by_asset: dict) -> io.BytesIO:
    """Generate a PDF report for ticket search results."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    import os

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=18, spaceAfter=6, textColor=colors.HexColor('#1e40af'))
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#6b7280'), alignment=1)
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=14, spaceBefore=12, spaceAfter=6, textColor=colors.HexColor('#1f2937'))
    subsection_style = ParagraphStyle('Subsection', parent=styles['Heading3'], fontSize=11, spaceBefore=8, spaceAfter=4, textColor=colors.HexColor('#374151'))
    normal_style = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=9, spaceAfter=4)

    logo_path = "/opt/boobytrap/static/img/fiducia_logo.png"
    if os.path.exists(logo_path):
        img = Image(logo_path, width=1.5*inch, height=1.5*inch)
        img.hAlign = 'RIGHT'
        story.append(img)

    story.append(Paragraph("Ticket Change Report", title_style))
    story.append(Paragraph("CIP-010 Compliance Documentation", subtitle_style))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", subtitle_style))
    story.append(Spacer(1, 0.3*inch))

    total_changes = sum(len(a["changes"]) for a in results_by_asset.values())
    total_assets = len(results_by_asset)

    summary_data = [
        ["Ticket Number:", ticket_number],
        ["Total Assets:", str(total_assets)],
        ["Total Changes:", str(total_changes)]
    ]

    summary_table = Table(summary_data, colWidths=[1.5*inch, 5*inch])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f3f4f6')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#d1d5db')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.3*inch))

    for asset_name in sorted(results_by_asset.keys()):
        asset_data = results_by_asset[asset_name]
        changes = asset_data["changes"]

        story.append(Paragraph(f"Asset: {asset_name}", section_style))

        if asset_data.get("asset_fqdn"):
            story.append(Paragraph(f"FQDN: {asset_data['asset_fqdn']}", normal_style))
        if asset_data.get("group"):
            story.append(Paragraph(f"Group: {asset_data['group']}", normal_style))

        story.append(Paragraph(f"Changes: {len(changes)}", normal_style))
        story.append(Spacer(1, 0.1*inch))

        for i, change in enumerate(changes, 1):
            story.append(Paragraph(f"Change {i}: {change.get('field', 'Unknown Field')}", subsection_style))

            change_data = []
            change_data.append(["Type:", change.get("change_type", "modified")])
            status = change.get("status", "unknown").upper()
            change_data.append(["Status:", status])

            old_val = change.get("old_value")
            if old_val is not None and old_val != 'null' and str(old_val).lower() != 'null':
                old_str = json.dumps(old_val) if isinstance(old_val, (list, dict)) else str(old_val)
                if len(old_str) > 80:
                    old_str = old_str[:77] + "..."
                change_data.append(["Old Value:", old_str])

            new_val = change.get("new_value")
            if new_val is not None and new_val != 'null' and str(new_val).lower() != 'null':
                new_str = json.dumps(new_val) if isinstance(new_val, (list, dict)) else str(new_val)
                if len(new_str) > 80:
                    new_str = new_str[:77] + "..."
                change_data.append(["New Value:", new_str])

            if change.get("approved_by"):
                change_data.append(["Reviewed By:", change["approved_by"]])
            if change.get("resolution_notes"):
                change_data.append(["Notes:", change["resolution_notes"]])

            change_table = Table(change_data, colWidths=[1.2*inch, 5.3*inch])
            change_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fafb')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ]))
            story.append(change_table)
            story.append(Spacer(1, 0.1*inch))

        story.append(Spacer(1, 0.2*inch))

    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("--- End of Ticket Report ---", subtitle_style))

    doc.build(story)
    buffer.seek(0)
    return buffer


@router.get("/promotion-pdf/{audit_log_id}")
async def generate_promotion_pdf(
    audit_log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate a PDF report for a baseline promotion event."""
    from database.models import AuditLog
    
    # Get the audit log entry
    audit = db.query(AuditLog).filter(AuditLog.id == audit_log_id).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Promotion record not found")
    
    if audit.action != "finalize_baselines":
        raise HTTPException(status_code=400, detail="Not a baseline promotion record")
    
    # Parse the details
    try:
        details = json.loads(audit.details_json) if audit.details_json else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Could not parse promotion details")
    
    finalized_assets = details.get("finalized_assets", [])
    if not finalized_assets:
        raise HTTPException(status_code=404, detail="No assets in promotion record")
    
    # Get username from audit log
    closed_by = "Unknown"
    if audit.user_id:
        user = db.query(User).filter(User.id == audit.user_id).first()
        if user:
            closed_by = user.username
    
    # Generate the PDF
    pdf_buffer = _generate_promotion_pdf(finalized_assets, audit.timestamp, closed_by)
    
    filename = f"baseline_promotion_{audit_log_id}_{audit.timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


def _generate_promotion_pdf(finalized_assets: list, promotion_time: datetime, promoted_by: str) -> io.BytesIO:
    """Generate a PDF report for baseline promotion."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, HRFlowable
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    import os

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch,
                           leftMargin=0.5*inch, rightMargin=0.5*inch)

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=20, spaceAfter=6,
                                  alignment=TA_CENTER, textColor=colors.HexColor('#1e40af'))
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=10,
                                     alignment=TA_CENTER, textColor=colors.HexColor('#6b7280'))
    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=14,
                                    spaceBefore=12, spaceAfter=6, textColor=colors.HexColor('#1e40af'),
                                    borderColor=colors.HexColor('#1e40af'), borderWidth=1,
                                    borderPadding=5, backColor=colors.HexColor('#eff6ff'))
    change_header_style = ParagraphStyle('ChangeHeader', parent=styles['Heading3'], fontSize=11,
                                          spaceBefore=8, spaceAfter=4, textColor=colors.white,
                                          backColor=colors.HexColor('#374151'), borderPadding=5)
    label_style = ParagraphStyle('Label', parent=styles['Normal'], fontSize=9,
                                  textColor=colors.HexColor('#6b7280'), fontName='Helvetica-Bold')
    value_style = ParagraphStyle('Value', parent=styles['Normal'], fontSize=9,
                                  textColor=colors.HexColor('#1f2937'), leftIndent=10)
    before_style = ParagraphStyle('Before', parent=styles['Normal'], fontSize=9,
                                   textColor=colors.HexColor('#dc2626'), leftIndent=15)
    after_style = ParagraphStyle('After', parent=styles['Normal'], fontSize=9,
                                  textColor=colors.HexColor('#16a34a'), leftIndent=15)
    removed_style = ParagraphStyle('Removed', parent=styles['Normal'], fontSize=8,
                                    textColor=colors.HexColor('#dc2626'), leftIndent=20,
                                    backColor=colors.HexColor('#fef2f2'), borderPadding=3)
    added_style = ParagraphStyle('Added', parent=styles['Normal'], fontSize=8,
                                  textColor=colors.HexColor('#16a34a'), leftIndent=20,
                                  backColor=colors.HexColor('#f0fdf4'), borderPadding=3)
    normal_style = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=9, spaceAfter=4)

    story = []

    # Logo - try multiple paths
    logo_paths = [
        "/home/michael/Fiducia-LZ/static/fiducia-logo.jpg",
        "/opt/boobytrap/static/img/fiducia_logo.png",
        "static/fiducia-logo.jpg"
    ]
    logo_found = False
    for logo_path in logo_paths:
        if os.path.exists(logo_path):
            try:
                img = Image(logo_path, width=1.5*inch, height=1.5*inch)
                img.hAlign = 'CENTER'
                story.append(img)
                story.append(Spacer(1, 0.2*inch))
                logo_found = True
                break
            except:
                pass

    # Title
    story.append(Paragraph("BASELINE PROMOTION REPORT", title_style))
    story.append(Paragraph(f"Generated: {promotion_time.strftime('%Y-%m-%d %H:%M:%S')} UTC", subtitle_style))
    story.append(Paragraph(f"Fiducia v{settings.APP_VERSION} - CIP-010 Compliance Documentation", subtitle_style))
    story.append(Spacer(1, 0.3*inch))

    # Summary
    total_changes = sum(a.get('changes_finalized', 0) for a in finalized_assets)

    # Collect all tickets
    all_tickets = set()
    for asset in finalized_assets:
        for change in asset.get('changes', []):
            if change.get('ticket_number'):
                all_tickets.add(change['ticket_number'])

    summary_data = [
        ["Promoted By:", promoted_by],
        ["Assets Promoted:", str(len(finalized_assets))],
        ["Total Changes:", str(total_changes)],
    ]
    if all_tickets:
        summary_data.append(["Related Tickets:", ", ".join(sorted(all_tickets))])

    summary_table = Table(summary_data, colWidths=[1.5*inch, 5.5*inch])
    summary_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f3f4f6')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#1e40af')),
        ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#d1d5db')),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4*inch))

    # Helper function to format values for PDF
    def format_value_for_pdf(val):
        if val is None:
            return "(none)"
        if isinstance(val, dict):
            lines = []
            for k, v in val.items():
                lines.append(f"  {k}: {v}")
            return "\n".join(lines) if lines else "(empty object)"
        if isinstance(val, list):
            if not val:
                return "(empty list)"
            lines = []
            for item in val:
                if isinstance(item, dict):
                    item_str = ", ".join(f"{k}: {v}" for k, v in item.items())
                    lines.append(f"  • {{ {item_str} }}")
                else:
                    lines.append(f"  • {item}")
            return "\n".join(lines)
        return str(val)

    # Per-asset details
    for idx, asset in enumerate(finalized_assets, 1):
        if idx > 1:
            story.append(PageBreak())

        # Asset header
        story.append(Paragraph(f"Asset {idx}: {asset.get('name', 'Unknown')}", section_style))

        asset_info = []
        if asset.get('fqdn'):
            asset_info.append(["FQDN:", asset['fqdn']])
        if asset.get('group'):
            asset_info.append(["Team:", asset['group']])
        asset_info.append(["Changes Promoted:", str(asset.get('changes_finalized', 0))])

        if asset_info:
            asset_table = Table(asset_info, colWidths=[1.2*inch, 5.8*inch])
            asset_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(asset_table)

        story.append(Spacer(1, 0.15*inch))

        # Changes
        changes = asset.get('changes', [])
        for i, change in enumerate(changes, 1):
            # Change header with field name
            field_name = change.get('field', 'Unknown Field')
            change_type = change.get('change_type', 'modified').upper().replace('_', ' ')

            story.append(Paragraph(f"Change {i}: {field_name}", change_header_style))
            story.append(Spacer(1, 0.05*inch))

            # Change type
            story.append(Paragraph(f"<b>Type:</b> {change_type}", normal_style))

            # Handle array_modified changes
            if change.get('change_type', '').lower() == 'array_modified':
                items_added = change.get('items_added') or []
                items_removed = change.get('items_removed') or []

                if items_removed:
                    story.append(Spacer(1, 0.05*inch))
                    story.append(Paragraph(f"<b>REMOVED ({len(items_removed)} items):</b>", label_style))
                    for item in items_removed:
                        if isinstance(item, dict):
                            item_str = ", ".join(f"{k}: {v}" for k, v in item.items())
                            story.append(Paragraph(f"− {{ {item_str} }}", removed_style))
                        else:
                            story.append(Paragraph(f"− {item}", removed_style))

                if items_added:
                    story.append(Spacer(1, 0.05*inch))
                    story.append(Paragraph(f"<b>ADDED ({len(items_added)} items):</b>", label_style))
                    for item in items_added:
                        if isinstance(item, dict):
                            item_str = ", ".join(f"{k}: {v}" for k, v in item.items())
                            story.append(Paragraph(f"+ {{ {item_str} }}", added_style))
                        else:
                            story.append(Paragraph(f"+ {item}", added_style))
            else:
                # Standard old/new value display - FULL values, no truncation
                old_val = change.get('old_value')
                new_val = change.get('new_value')

                story.append(Spacer(1, 0.05*inch))
                story.append(Paragraph("<b>BEFORE:</b>", label_style))
                formatted_old = format_value_for_pdf(old_val)
                # Handle multi-line values
                for line in formatted_old.split('\n'):
                    story.append(Paragraph(line if line.strip() else "(none)", before_style))

                story.append(Spacer(1, 0.05*inch))
                story.append(Paragraph("<b>AFTER:</b>", label_style))
                formatted_new = format_value_for_pdf(new_val)
                for line in formatted_new.split('\n'):
                    story.append(Paragraph(line if line.strip() else "(none)", after_style))

            # Metadata table
            story.append(Spacer(1, 0.1*inch))
            meta_data = []
            if change.get('ticket_number'):
                meta_data.append(["Ticket #:", change['ticket_number']])
            if change.get('approved_by'):
                meta_data.append(["Approved By:", change['approved_by']])
            if change.get('approved_at'):
                meta_data.append(["Approved At:", change['approved_at']])
            if change.get('detected_at'):
                meta_data.append(["Detected:", change['detected_at']])
            if change.get('time_to_close_days') is not None:
                days = change['time_to_close_days']
                status = "Same day" if days == 0 else f"{days} day{'s' if days != 1 else ''}"
                meta_data.append(["Time to Close:", status])
            if change.get('resolution_notes'):
                meta_data.append(["Notes:", change['resolution_notes']])

            if meta_data:
                meta_table = Table(meta_data, colWidths=[1.2*inch, 5.8*inch])
                meta_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6b7280')),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f9fafb')),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
                ]))
                story.append(meta_table)

            story.append(Spacer(1, 0.15*inch))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#e5e7eb')))
            story.append(Spacer(1, 0.1*inch))

    # Footer
    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1e40af')))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("--- End of Baseline Promotion Report ---", subtitle_style))
    story.append(Paragraph(f"Fiducia v{settings.APP_VERSION} • CIP-010 Baseline Management", subtitle_style))

    doc.build(story)
    buffer.seek(0)
    return buffer
