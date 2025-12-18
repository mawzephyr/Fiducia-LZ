"""
System routes for CIP-010 Baseline Engine.

Provides dashboard stats, watcher control, and scheduler management.
"""
import json
import logging
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from sqlalchemy import func

logger = logging.getLogger(__name__)

from config import settings
from database import get_db, Asset, AssetState, Change, ChangeStatus, Group, SystemSetting, AuditLog
from api.schemas import DashboardStats, WatcherStats, SchedulerStatus
from api.routes.auth import get_current_user, get_current_admin, User

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get dashboard statistics."""
    
    # Total assets
    total_assets = db.query(Asset).count()
    
    # Assets by group
    assets_by_group = {}
    group_counts = db.query(
        Asset.group_id, func.count(Asset.id)
    ).group_by(Asset.group_id).all()
    
    for group_id, count in group_counts:
        assets_by_group[group_id or "unassigned"] = count
    
    # Assets by state
    assets_by_state = {}
    state_counts = db.query(
        Asset.current_state, func.count(Asset.id)
    ).group_by(Asset.current_state).all()
    
    for state, count in state_counts:
        assets_by_state[state.value] = count
    
    # Pending changes
    pending_changes = db.query(Change).filter(
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    ).count()
    
    # Pending by group
    pending_by_group = {}
    pending_query = db.query(
        Asset.group_id, func.count(Change.id)
    ).join(Change).filter(
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    ).group_by(Asset.group_id).all()
    
    for group_id, count in pending_query:
        pending_by_group[group_id or "unassigned"] = count
    
    # New assets (no group assigned)
    new_assets_queue = db.query(Asset).filter(Asset.group_id == None).count()

    # v4.0.0: Per-change compliance deadline tracking
    compliance_settings = get_compliance_settings(db)
    today = datetime.utcnow().date()

    # Count changes approaching deadline (within yellow threshold days)
    # Only count PENDING and INVESTIGATION changes (not already FAILED)
    warning_threshold = compliance_settings["yellow_threshold_days"]
    changes_approaching_deadline = db.query(Change).filter(
        Change.compliance_due_date != None,
        Change.compliance_due_date <= today + timedelta(days=warning_threshold),
        Change.compliance_due_date > today,
        Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION])
    ).count()

    # Count changes past deadline (FAILED status or past due date)
    changes_past_deadline = db.query(Change).filter(
        Change.status == ChangeStatus.FAILED
    ).count()

    # Approved changes awaiting finalization
    approved_changes = db.query(Change).filter(
        Change.status == ChangeStatus.APPROVED
    ).count()

    return DashboardStats(
        total_assets=total_assets,
        assets_by_group=assets_by_group,
        assets_by_state=assets_by_state,
        pending_changes=pending_changes,
        pending_by_group=pending_by_group,
        new_assets_queue=new_assets_queue,
        changes_approaching_deadline=changes_approaching_deadline,
        changes_past_deadline=changes_past_deadline,
        approved_changes=approved_changes
    )


@router.get("/groups")
async def get_groups(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all asset groups with counts."""
    groups = db.query(Group).all()
    
    result = []
    for group in groups:
        asset_count = db.query(Asset).filter(Asset.group_id == group.id).count()
        result.append({
            "id": group.id,
            "name": group.name,
            "color": group.color,
            "asset_count": asset_count
        })
    
    return result


@router.get("/watcher/status", response_model=WatcherStats)
async def get_watcher_status(
    current_user: User = Depends(get_current_user)
):
    """Get file watcher status and statistics."""
    from api.main import get_watcher_service
    
    watcher = get_watcher_service()
    
    if not watcher:
        return WatcherStats(
            is_running=False,
            files_processed=0,
            new_assets=0,
            updated_assets=0,
            errors=0,
            last_file=None,
            started_at=None
        )
    
    stats = watcher.get_stats()
    return WatcherStats(**stats)


@router.post("/watcher/start")
async def start_watcher(
    watch_path: str,
    current_user: User = Depends(get_current_admin)
):
    """Start the file watcher on a directory (admin only)."""
    from api.main import watcher_service, get_db_session
    from services.watcher import WatcherService
    
    global watcher_service
    
    if watcher_service and watcher_service.watcher and watcher_service.watcher.is_running():
        raise HTTPException(status_code=400, detail="Watcher already running")
    
    watcher_service = WatcherService(get_db_session)
    
    try:
        watcher_service.start(watch_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Directory not found: {watch_path}")
    
    return {"message": f"Watcher started on: {watch_path}"}


@router.post("/watcher/stop")
async def stop_watcher(
    current_user: User = Depends(get_current_admin)
):
    """Stop the file watcher (admin only)."""
    from api.main import get_watcher_service
    
    watcher = get_watcher_service()
    
    if not watcher:
        raise HTTPException(status_code=400, detail="No watcher service")
    
    watcher.stop()
    return {"message": "Watcher stopped"}


@router.get("/scheduler/status", response_model=SchedulerStatus)
async def get_scheduler_status(
    current_user: User = Depends(get_current_user)
):
    """Get scheduler status and upcoming jobs."""
    from api.main import get_scheduler_service
    
    scheduler = get_scheduler_service()
    
    if not scheduler:
        return SchedulerStatus(is_running=False, scheduled_jobs=[])
    
    return SchedulerStatus(
        is_running=scheduler.is_running(),
        scheduled_jobs=scheduler.get_scheduled_jobs()
    )


@router.post("/scheduler/run-check")
async def trigger_compliance_check(
    current_user: User = Depends(get_current_admin)
):
    """Manually trigger a compliance check (admin only)."""
    from api.main import get_scheduler_service

    scheduler = get_scheduler_service()

    if not scheduler:
        raise HTTPException(status_code=400, detail="Scheduler not available")

    try:
        result = scheduler.run_check_now(triggered_by=current_user.username)
        return {
            "message": "Compliance check completed",
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Check failed: {str(e)}")


@router.post("/scheduler/reload")
async def reload_scheduler(
    current_user: User = Depends(get_current_admin)
):
    """Reload scheduler configuration from database (admin only)."""
    from api.main import get_scheduler_service

    scheduler = get_scheduler_service()

    if not scheduler:
        raise HTTPException(status_code=400, detail="Scheduler not available")

    try:
        result = scheduler.reload_compliance_schedule()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Reload failed: {str(e)}")


def get_setting_value(db: Session, key: str, default, value_type=str):
    """Helper to get a setting value from DB with fallback to default."""
    setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if setting and setting.value is not None:
        try:
            if value_type == bool:
                return setting.value.lower() == 'true'
            elif value_type == int:
                return int(setting.value)
            return setting.value
        except (ValueError, AttributeError):
            return default
    return default


def get_compliance_settings(db: Session) -> dict:
    """Get all compliance settings with defaults from config."""
    return {
        "compliance_window_days": get_setting_value(db, "compliance_window_days", settings.COMPLIANCE_WINDOW_DAYS, int),
        "green_threshold_days": get_setting_value(db, "green_threshold_days", settings.GREEN_THRESHOLD_DAYS, int),
        "yellow_threshold_days": get_setting_value(db, "yellow_threshold_days", settings.YELLOW_THRESHOLD_DAYS, int),
        "critical_threshold_days": get_setting_value(db, "critical_threshold_days", settings.CRITICAL_THRESHOLD_DAYS, int),
        "require_resolution_notes": get_setting_value(db, "require_resolution_notes", settings.REQUIRE_RESOLUTION_NOTES, bool),
        "auto_pnci_on_failure": get_setting_value(db, "auto_pnci_on_failure", settings.AUTO_PNCI_ON_FAILURE, bool),
        "allow_deadline_extension": get_setting_value(db, "allow_deadline_extension", settings.ALLOW_DEADLINE_EXTENSION, bool),
        "max_extension_days": get_setting_value(db, "max_extension_days", settings.MAX_EXTENSION_DAYS, int),
        "show_compliance_percentage": get_setting_value(db, "show_compliance_percentage", settings.SHOW_COMPLIANCE_PERCENTAGE, bool),
        "historical_retention_days": get_setting_value(db, "historical_retention_days", settings.HISTORICAL_RETENTION_DAYS, int),
    }


def get_schedule_config(db: Session) -> dict:
    """Get the current schedule configuration."""
    from services.scheduler import get_next_scheduled_check_date, format_schedule_description

    schedule_type = get_setting_value(db, "compliance_check_type", "day_of_month", str)
    days_str = get_setting_value(db, "compliance_check_days", "1,15", str)
    patterns_json = get_setting_value(db, "compliance_check_patterns", "[]", str)
    hour = get_setting_value(db, "compliance_check_hour", 2, int)
    minute = get_setting_value(db, "compliance_check_minute", 0, int)
    enabled = get_setting_value(db, "compliance_check_enabled", True, bool)

    # Parse days
    try:
        days = [int(d.strip()) for d in days_str.split(',') if d.strip()]
    except:
        days = [1, 15]

    # Parse patterns
    try:
        patterns = json.loads(patterns_json) if patterns_json else []
    except:
        patterns = []

    # Build config object
    if schedule_type == "weekday_pattern":
        config = {"type": "weekday_pattern", "patterns": patterns}
    else:
        config = {"type": "day_of_month", "days": days}

    # Calculate next check date
    from datetime import date
    next_check = get_next_scheduled_check_date(config)
    next_check_str = next_check.isoformat() if next_check else None

    return {
        "enabled": enabled,
        "type": schedule_type,
        "days": days,
        "patterns": patterns,
        "hour": hour,
        "minute": minute,
        "description": format_schedule_description(config),
        "next_check_date": next_check_str,
        "config": config  # Full config object for frontend
    }


@router.get("/config")
async def get_config(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current application configuration (non-sensitive)."""
    compliance = get_compliance_settings(db)
    schedule = get_schedule_config(db)

    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "scheduled_check_days": schedule["days"],  # For backwards compatibility
        "schedule_config": schedule,  # New full schedule config
        "watch_directory": settings.WATCH_DIRECTORY,
        "asset_groups": settings.ASSET_GROUPS,
        **compliance
    }


@router.get("/schedule")
async def get_schedule(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current schedule configuration with next check date."""
    return get_schedule_config(db)


@router.get("/settings/compliance")
async def get_compliance_settings_endpoint(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get all compliance-related settings with descriptions (admin only)."""
    return {
        "settings": get_compliance_settings(db),
        "descriptions": {
            "compliance_window_days": "Number of days allowed to resolve an investigation before the asset is marked as FAILED (non-compliant). CIP-010 typically requires 35 days.",
            "green_threshold_days": "Days remaining threshold for 'On Track' status (green). Assets with more than this many days remaining show as green.",
            "yellow_threshold_days": "Days remaining threshold for 'Warning' status (yellow). Assets with days remaining between this and green threshold show as yellow.",
            "critical_threshold_days": "Days remaining threshold for 'Critical' status (orange). Assets with days remaining between this and yellow threshold show as orange. Below this is red/overdue.",
            "require_resolution_notes": "When enabled, users must provide notes when approving or rejecting changes. Helps maintain audit trail.",
            "auto_pnci_on_failure": "When enabled, automatically generates a PNCI (Potential Non-Compliance Identification) report when an asset moves to FAILED status.",
            "allow_deadline_extension": "When enabled, allows authorized users to extend the compliance deadline for specific assets with justification.",
            "max_extension_days": "Maximum number of days that can be added when extending a compliance deadline.",
            "show_compliance_percentage": "When enabled, displays the overall compliance percentage on the dashboard.",
            "historical_retention_days": "Number of days to retain historical compliance data for reporting purposes.",
        },
        "defaults": {
            "compliance_window_days": settings.COMPLIANCE_WINDOW_DAYS,
            "green_threshold_days": settings.GREEN_THRESHOLD_DAYS,
            "yellow_threshold_days": settings.YELLOW_THRESHOLD_DAYS,
            "critical_threshold_days": settings.CRITICAL_THRESHOLD_DAYS,
            "require_resolution_notes": settings.REQUIRE_RESOLUTION_NOTES,
            "auto_pnci_on_failure": settings.AUTO_PNCI_ON_FAILURE,
            "allow_deadline_extension": settings.ALLOW_DEADLINE_EXTENSION,
            "max_extension_days": settings.MAX_EXTENSION_DAYS,
            "show_compliance_percentage": settings.SHOW_COMPLIANCE_PERCENTAGE,
            "historical_retention_days": settings.HISTORICAL_RETENTION_DAYS,
        }
    }


@router.get("/database")
async def get_database_status(
    current_user: User = Depends(get_current_admin)
):
    """Get database connection info (admin only)."""
    from database import get_database_info
    return get_database_info()


@router.get("/settings")
async def get_system_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get all system settings (admin only)."""
    settings_list = db.query(SystemSetting).all()
    return {
        setting.key: {
            "value": setting.value,
            "description": setting.description,
            "updated_at": setting.updated_at.isoformat() if setting.updated_at else None,
            "updated_by": setting.updated_by
        }
        for setting in settings_list
    }


# ============================================================
# SMTP EMAIL SETTINGS (must be before /settings/{key} routes)
# ============================================================

@router.get("/settings/smtp")
async def get_smtp_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get SMTP configuration (admin only). Password is masked."""
    smtp_keys = [
        'smtp_enabled', 'smtp_server', 'smtp_port', 'smtp_use_tls',
        'smtp_use_ssl', 'smtp_username', 'smtp_password',
        'smtp_from_address', 'smtp_from_name', 'smtp_timeout'
    ]

    settings_dict = {}
    for key in smtp_keys:
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if key == 'smtp_password' and setting and setting.value:
            settings_dict[key] = "********" if setting.value else ""
        else:
            settings_dict[key] = setting.value if setting else None

    defaults = {
        "smtp_enabled": "false",
        "smtp_port": "587",
        "smtp_use_tls": "true",
        "smtp_use_ssl": "false",
        "smtp_from_name": "Fiducia",
        "smtp_timeout": "30"
    }

    return {
        "smtp_enabled": settings_dict.get('smtp_enabled', defaults['smtp_enabled']) == 'True',
        "smtp_server": settings_dict.get('smtp_server', ''),
        "smtp_port": settings_dict.get('smtp_port', defaults['smtp_port']),
        "smtp_use_tls": settings_dict.get('smtp_use_tls', defaults['smtp_use_tls']) == 'True',
        "smtp_use_ssl": settings_dict.get('smtp_use_ssl', defaults['smtp_use_ssl']) == 'True',
        "smtp_username": settings_dict.get('smtp_username', ''),
        "smtp_password": settings_dict.get('smtp_password', ''),
        "smtp_from_address": settings_dict.get('smtp_from_address', ''),
        "smtp_from_name": settings_dict.get('smtp_from_name', defaults['smtp_from_name'])
    }


@router.put("/settings/smtp")
async def update_smtp_settings(
    settings_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Update SMTP configuration (admin only)."""
    allowed_keys = [
        'smtp_enabled', 'smtp_server', 'smtp_port', 'smtp_use_tls',
        'smtp_use_ssl', 'smtp_username', 'smtp_password',
        'smtp_from_address', 'smtp_from_name', 'smtp_timeout'
    ]

    updated = []
    for key, value in settings_data.items():
        if key not in allowed_keys:
            continue
        if key == 'smtp_password' and value == "********":
            continue

        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if setting:
            setting.value = str(value) if value is not None else None
            setting.updated_at = datetime.utcnow()
            setting.updated_by = current_user.username
        else:
            setting = SystemSetting(
                key=key,
                value=str(value) if value is not None else None,
                description=f"SMTP setting: {key}",
                updated_by=current_user.username
            )
            db.add(setting)
        updated.append(key)

    db.commit()

    try:
        from database import SessionLocal
        from services.email_service import EmailService
        email_service = EmailService(lambda: SessionLocal())
        email_service.clear_cache()
    except Exception:
        pass

    return {"message": f"Updated {len(updated)} SMTP settings", "updated": updated}


@router.post("/settings/smtp/test")
async def test_smtp_connection(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Test SMTP connection with current settings (admin only)."""
    from database import SessionLocal
    from services.email_service import EmailService

    email_service = EmailService(lambda: SessionLocal())
    result = email_service.test_connection()
    return result


@router.post("/settings/smtp/test-email")
async def send_test_email(
    to: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Send a test email to verify configuration (admin only)."""
    from database import SessionLocal
    from services.email_service import EmailService

    email_service = EmailService(lambda: SessionLocal())
    result = email_service.send_test_email(to)
    return result


@router.get("/settings/email-alerts")
async def get_email_alert_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get email alert configuration (admin only)."""
    alert_keys = [
        'alert_emails_compliance', 'alert_emails_managers',
        'alert_approaching_enabled', 'alert_failed_enabled',
        'alert_weekly_enabled', 'alert_weekly_day', 'alert_weekly_time'
    ]

    settings_dict = {}
    for key in alert_keys:
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        settings_dict[key] = setting.value if setting else None

    return {
        "emails_compliance": settings_dict.get('alert_emails_compliance', ''),
        "emails_managers": settings_dict.get('alert_emails_managers', ''),
        "approaching_enabled": settings_dict.get('alert_approaching_enabled', 'true') == 'True',
        "failed_enabled": settings_dict.get('alert_failed_enabled', 'true') == 'True',
        "weekly_enabled": settings_dict.get('alert_weekly_enabled', 'true') == 'True',
        "weekly_day": settings_dict.get('alert_weekly_day', '0'),
        "weekly_time": settings_dict.get('alert_weekly_time', '08:00')
    }


@router.put("/settings/email-alerts")
async def update_email_alert_settings(
    settings_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Update email alert configuration (admin only)."""
    # Map frontend keys to database keys
    key_mapping = {
        'emails_compliance': 'alert_emails_compliance',
        'emails_managers': 'alert_emails_managers',
        'approaching_enabled': 'alert_approaching_enabled',
        'failed_enabled': 'alert_failed_enabled',
        'weekly_enabled': 'alert_weekly_enabled',
        'weekly_day': 'alert_weekly_day',
        'weekly_time': 'alert_weekly_time'
    }

    updated = []
    for frontend_key, value in settings_data.items():
        db_key = key_mapping.get(frontend_key, frontend_key)
        if db_key not in key_mapping.values():
            continue

        setting = db.query(SystemSetting).filter(SystemSetting.key == db_key).first()
        if setting:
            setting.value = str(value) if value is not None else None
            setting.updated_at = datetime.utcnow()
            setting.updated_by = current_user.username
        else:
            setting = SystemSetting(
                key=db_key,
                value=str(value) if value is not None else None,
                description=f"Email alert setting: {db_key}",
                updated_by=current_user.username
            )
            db.add(setting)
        updated.append(db_key)

    db.commit()

    try:
        from database import SessionLocal
        from services.email_service import EmailService
        email_service = EmailService(lambda: SessionLocal())
        email_service.clear_cache()
    except Exception:
        pass

    if any(k in updated for k in ['alert_weekly_day', 'alert_weekly_time', 'alert_weekly_enabled']):
        try:
            from api.main import get_scheduler_service
            scheduler = get_scheduler_service()
            if scheduler:
                scheduler.reload_weekly_report_schedule()
        except Exception:
            pass

    return {"message": f"Updated {len(updated)} alert settings", "updated": updated}


# ============================================================
# SYSLOG SETTINGS (specific routes must be before generic /settings/{key})
# ============================================================

@router.get("/settings/syslog")
async def get_syslog_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get syslog configuration (admin only)."""
    from services.syslog import SYSLOG_EVENT_TYPES

    # Get all syslog settings
    syslog_keys = [
        'syslog_enabled', 'syslog_server', 'syslog_port', 'syslog_protocol',
        'syslog_facility', 'syslog_tls_verify', 'syslog_tls_ca_cert', 'syslog_enabled_events'
    ]

    settings = {}
    for key in syslog_keys:
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if setting:
            settings[key] = setting.value
        else:
            # Defaults
            defaults = {
                'syslog_enabled': 'false',
                'syslog_server': '',
                'syslog_port': '514',
                'syslog_protocol': 'udp',
                'syslog_facility': '16',
                'syslog_tls_verify': 'true',
                'syslog_tls_ca_cert': '',
                'syslog_enabled_events': '{}'
            }
            settings[key] = defaults.get(key, '')

    # Parse enabled events JSON
    try:
        enabled_events = json.loads(settings.get('syslog_enabled_events', '{}'))
    except json.JSONDecodeError:
        enabled_events = {}

    return {
        "enabled": settings.get('syslog_enabled', 'false').lower() == 'true',
        "server": settings.get('syslog_server', ''),
        "port": int(settings.get('syslog_port', '514')),
        "protocol": settings.get('syslog_protocol', 'udp'),
        "facility": int(settings.get('syslog_facility', '16')),
        "tls_verify": settings.get('syslog_tls_verify', 'true').lower() == 'true',
        "tls_ca_cert": settings.get('syslog_tls_ca_cert', ''),
        "enabled_events": enabled_events,
        "event_types": [
            {"id": et[0], "name": et[1], "description": et[2]}
            for et in SYSLOG_EVENT_TYPES
        ]
    }


@router.put("/settings/syslog")
async def update_syslog_settings(
    settings_data: dict = Body(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Update syslog configuration (admin only)."""
    from services.syslog import get_syslog_service

    # Map input keys to database keys
    key_mapping = {
        'enabled': 'syslog_enabled',
        'server': 'syslog_server',
        'port': 'syslog_port',
        'protocol': 'syslog_protocol',
        'facility': 'syslog_facility',
        'tls_verify': 'syslog_tls_verify',
        'tls_ca_cert': 'syslog_tls_ca_cert',
        'enabled_events': 'syslog_enabled_events'
    }

    updated_keys = []

    for input_key, db_key in key_mapping.items():
        if input_key in settings_data:
            value = settings_data[input_key]

            # Convert to string for storage
            if input_key == 'enabled_events':
                value = json.dumps(value) if isinstance(value, dict) else str(value)
            elif isinstance(value, bool):
                value = 'true' if value else 'false'
            else:
                value = str(value)

            # Update or create setting
            setting = db.query(SystemSetting).filter(SystemSetting.key == db_key).first()
            if setting:
                setting.value = value
                setting.updated_at = datetime.utcnow()
                setting.updated_by = current_user.username
            else:
                setting = SystemSetting(
                    key=db_key,
                    value=value,
                    description=f"Syslog setting: {input_key}",
                    updated_by=current_user.username
                )
                db.add(setting)

            updated_keys.append(db_key)

    db.commit()

    # Clear syslog service cache
    syslog_svc = get_syslog_service()
    if syslog_svc:
        syslog_svc.clear_cache()

    # Create audit log
    from database import AuditLog
    audit = AuditLog(
        user_id=current_user.id,
        action="update_setting",
        action_detail=f"Updated syslog settings: {', '.join(updated_keys)}",
        details_json=json.dumps({"updated_keys": updated_keys})
    )
    db.add(audit)
    db.commit()

    return {
        "message": "Syslog settings updated successfully",
        "updated_keys": updated_keys
    }


@router.post("/settings/syslog/test")
async def test_syslog_connection(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Test syslog connection with current settings (admin only)."""
    from services.syslog import get_syslog_service

    syslog_svc = get_syslog_service()
    if not syslog_svc:
        raise HTTPException(status_code=500, detail="Syslog service not initialized")

    # Clear cache to use latest settings
    syslog_svc.clear_cache()

    result = syslog_svc.test_connection()

    return result


@router.get("/settings/syslog/events")
async def get_syslog_event_types(
    current_user: User = Depends(get_current_admin)
):
    """Get list of all available syslog event types with descriptions."""
    from services.syslog import SYSLOG_EVENT_TYPES

    return {
        "event_types": [
            {"id": et[0], "name": et[1], "description": et[2]}
            for et in SYSLOG_EVENT_TYPES
        ]
    }


# ============================================================
# GENERIC SETTINGS ENDPOINTS (must be after specific routes)
# ============================================================

@router.get("/settings/{key}")
async def get_system_setting(
    key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get a specific system setting (admin only)."""
    setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    if not setting:
        return {"key": key, "value": None, "description": None}
    return {
        "key": setting.key,
        "value": setting.value,
        "description": setting.description,
        "updated_at": setting.updated_at.isoformat() if setting.updated_at else None,
        "updated_by": setting.updated_by
    }


@router.put("/settings/{key}")
async def update_system_setting(
    key: str,
    value: str,
    description: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Update a system setting (admin only)."""
    from database import AuditLog

    setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    old_value = setting.value if setting else None

    if setting:
        setting.value = value
        if description:
            setting.description = description
        setting.updated_by = current_user.username
    else:
        setting = SystemSetting(
            key=key,
            value=value,
            description=description or f"Setting: {key}",
            updated_by=current_user.username
        )
        db.add(setting)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        action="update_setting",
        action_detail=f"Updated {key}: {old_value} -> {value}"
    )
    db.add(audit)

    db.commit()
    db.refresh(setting)

    # If this is the watch folder, notify scheduler to update
    if key == "watch_folder_path":
        try:
            from api.main import get_scheduler_service
            scheduler = get_scheduler_service()
            if scheduler:
                scheduler.update_watch_folder(value)
        except Exception as e:
            logger.warning(f"Could not update scheduler watch folder: {e}")

    return {
        "key": setting.key,
        "value": setting.value,
        "description": setting.description,
        "message": f"Setting '{key}' updated successfully"
    }


@router.post("/settings/watch-folder/scan")
async def trigger_folder_scan(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Manually trigger a folder scan (admin only)."""
    from api.main import get_scheduler_service

    scheduler = get_scheduler_service()
    if not scheduler:
        raise HTTPException(status_code=400, detail="Scheduler not available")

    # Get the watch folder path from settings
    setting = db.query(SystemSetting).filter(SystemSetting.key == "watch_folder_path").first()
    if not setting or not setting.value:
        raise HTTPException(status_code=400, detail="Watch folder path not configured")

    try:
        result = scheduler.scan_folder_now(setting.value)
        return {
            "message": "Folder scan completed",
            "result": result
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"Watch folder not found: {setting.value}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/settings/ldap/test")
async def test_ldap_connection(
    current_user: User = Depends(get_current_admin)
):
    """Test LDAP connection with current settings (admin only)."""
    from database import SessionLocal
    from services.ldap_auth import LDAPAuthService

    ldap_service = LDAPAuthService(lambda: SessionLocal())
    result = ldap_service.test_connection()

    if result['success']:
        return result
    else:
        raise HTTPException(status_code=400, detail=result['message'])


@router.get("/settings/ldap/status")
async def get_ldap_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get LDAP configuration status (admin only)."""
    from database import SessionLocal
    from services.ldap_auth import LDAPAuthService

    ldap_service = LDAPAuthService(lambda: SessionLocal())

    # Get relevant settings
    ldap_settings = {}
    for key in ['ldap_enabled', 'ldap_server', 'ldap_port', 'ldap_use_ssl',
                'ldap_user_base_dn', 'ldap_group_base_dn', 'ldap_cache_hours']:
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        ldap_settings[key] = setting.value if setting else None

    # Count cached LDAP users
    from database import User as UserModel
    cached_users = db.query(UserModel).filter(UserModel.created_by == 'ldap_sync').count()

    return {
        "enabled": ldap_service.is_ldap_enabled(),
        "server": ldap_settings.get('ldap_server'),
        "port": ldap_settings.get('ldap_port', '389'),
        "use_ssl": ldap_settings.get('ldap_use_ssl', 'false'),
        "user_base_dn": ldap_settings.get('ldap_user_base_dn'),
        "group_base_dn": ldap_settings.get('ldap_group_base_dn'),
        "cache_hours": ldap_settings.get('ldap_cache_hours', '168'),
        "cached_users": cached_users
    }


# ============================================================
# ACTIVE USERS (for maintenance warnings)
# ============================================================

@router.get("/users/active")
async def get_active_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get users who are currently logged in (admin only).

    Returns users whose last_login is within the token validity period (8 hours).
    """
    from database import User as UserModel

    # Token validity period from settings
    cutoff = datetime.utcnow() - timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Get users logged in within the validity period
    active_users = db.query(UserModel).filter(
        UserModel.last_login >= cutoff,
        UserModel.is_active == True
    ).order_by(UserModel.last_login.desc()).all()

    result = []
    for user in active_users:
        minutes_ago = int((datetime.utcnow() - user.last_login).total_seconds() / 60)
        if minutes_ago < 60:
            time_ago = f"{minutes_ago}m ago"
        else:
            hours_ago = minutes_ago // 60
            time_ago = f"{hours_ago}h ago"

        result.append({
            "user_id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "group": user.group,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "time_ago": time_ago
        })

    return {
        "active_users": result,
        "count": len(result),
        "validity_hours": settings.ACCESS_TOKEN_EXPIRE_MINUTES // 60
    }


# ============================================================
# USER AUDIT LOG
# ============================================================

@router.get("/audit/users")
async def get_user_audit_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get audit summary by user (admin only)."""
    from database import User as UserModel

    # Get all users with their action counts
    users = db.query(UserModel).all()

    result = []
    for user in users:
        # Count actions by this user
        action_counts = db.query(
            AuditLog.action, func.count(AuditLog.id)
        ).filter(
            AuditLog.user_id == user.id
        ).group_by(AuditLog.action).all()

        total_actions = sum(count for _, count in action_counts)

        # Get most recent action
        last_action = db.query(AuditLog).filter(
            AuditLog.user_id == user.id
        ).order_by(AuditLog.timestamp.desc()).first()

        result.append({
            "user_id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role,
            "total_actions": total_actions,
            "action_breakdown": {action: count for action, count in action_counts},
            "last_action": last_action.action if last_action else None,
            "last_action_time": last_action.timestamp.isoformat() if last_action else None
        })

    # Sort by total actions descending
    result.sort(key=lambda x: x['total_actions'], reverse=True)

    return {"users": result}


@router.get("/audit/users/{user_id}")
async def get_user_audit_detail(
    user_id: int,
    limit: int = 100,
    offset: int = 0,
    action_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get detailed audit log for a specific user (admin only)."""
    from database import User as UserModel

    # Verify user exists
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Build query
    query = db.query(AuditLog).filter(AuditLog.user_id == user_id)

    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    # Get total count
    total = query.count()

    # Get paginated results
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    # Format results with asset names
    result = []
    for log in logs:
        asset_name = None
        if log.asset_id:
            asset = db.query(Asset).filter(Asset.id == log.asset_id).first()
            asset_name = asset.asset_name if asset else f"Asset #{log.asset_id} (deleted)"

        result.append({
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "action": log.action,
            "action_detail": log.action_detail,
            "asset_id": log.asset_id,
            "asset_name": asset_name,
            "change_id": log.change_id,
            "ip_address": log.ip_address,
            "details": json.loads(log.details_json) if log.details_json else None
        })

    return {
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "role": user.role
        },
        "total": total,
        "offset": offset,
        "limit": limit,
        "logs": result
    }


@router.get("/audit/actions")
async def get_audit_action_types(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """Get list of all action types in the audit log (admin only)."""
    actions = db.query(
        AuditLog.action, func.count(AuditLog.id)
    ).group_by(AuditLog.action).order_by(func.count(AuditLog.id).desc()).all()

    return {
        "actions": [
            {"action": action, "count": count, "label": action.replace("_", " ").title()}
            for action, count in actions
        ]
    }


def sync_asset_state_from_changes(db: Session, asset: Asset) -> str:
    """
    Sync an asset's state based on its actual change statuses.

    Asset state should reflect:
    - INVESTIGATION: if asset has at least one change with status=INVESTIGATION
    - COMPLIANT: if asset has no pending/investigation changes
    - Unchanged: if asset has only pending changes (awaiting review)

    Returns the action taken: 'unchanged', 'to_compliant', 'to_investigation'
    """
    # Count changes by status
    investigation_count = db.query(Change).filter(
        Change.asset_id == asset.id,
        Change.status == ChangeStatus.INVESTIGATION
    ).count()

    pending_count = db.query(Change).filter(
        Change.asset_id == asset.id,
        Change.status == ChangeStatus.PENDING
    ).count()

    # Determine correct state
    if investigation_count > 0:
        # Has investigation changes - should be in INVESTIGATION state
        if asset.current_state != AssetState.INVESTIGATION:
            asset.current_state = AssetState.INVESTIGATION
            asset.state_changed_at = datetime.utcnow()
            return 'to_investigation'
    elif pending_count == 0:
        # No pending or investigation changes - should be COMPLIANT
        if asset.current_state == AssetState.INVESTIGATION:
            asset.current_state = AssetState.COMPLIANT
            asset.state_changed_at = datetime.utcnow()
            asset.compliance_due_date = None
            return 'to_compliant'
    # If has pending changes but no investigation, leave state as-is
    # (could be ACTIVE, COMPLIANT, etc.)

    return 'unchanged'


@router.post("/sync-asset-states")
async def sync_all_asset_states(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    """
    Sync all asset states to match their actual change statuses (admin only).

    Fixes orphaned assets that are in INVESTIGATION state but have no
    changes with INVESTIGATION status.
    """
    # Get all non-retired assets
    assets = db.query(Asset).filter(
        Asset.current_state != AssetState.RETIRED
    ).all()

    results = {
        "total_checked": len(assets),
        "to_compliant": [],
        "to_investigation": [],
        "unchanged": 0
    }

    for asset in assets:
        action = sync_asset_state_from_changes(db, asset)
        if action == 'to_compliant':
            results["to_compliant"].append({
                "id": asset.id,
                "name": asset.asset_name
            })
        elif action == 'to_investigation':
            results["to_investigation"].append({
                "id": asset.id,
                "name": asset.asset_name
            })
        else:
            results["unchanged"] += 1

    # Audit log if any changes were made
    if results["to_compliant"] or results["to_investigation"]:
        audit = AuditLog(
            user_id=current_user.id,
            action="sync_asset_states",
            action_detail=f"Synced {len(results['to_compliant'])} assets to COMPLIANT, {len(results['to_investigation'])} to INVESTIGATION",
            details_json=json.dumps(results)
        )
        db.add(audit)

    db.commit()

    return {
        "message": f"Synced {results['total_checked']} assets",
        "fixed_to_compliant": len(results["to_compliant"]),
        "fixed_to_investigation": len(results["to_investigation"]),
        "details": results
    }
