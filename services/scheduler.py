"""
Scheduler Service for CIP-010 Baseline Engine.

Handles automated baseline checks on configurable days (e.g., 1st and 15th of month)
or on specific weekday occurrences (e.g., 1st and 3rd Tuesday).
Generates compliance reports and tracks investigation states.
Also handles periodic folder scanning for new baseline files.
"""
import logging
import os
import calendar
from datetime import datetime, date, timedelta
from typing import Optional, Callable, List, Union
from pathlib import Path
import json

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from config import settings
from services.email_service import EmailService

logger = logging.getLogger(__name__)


# Weekday names for display and parsing
WEEKDAY_NAMES = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
WEEKDAY_ABBREV = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']


def get_nth_weekday_of_month(year: int, month: int, weekday: int, occurrence: int) -> Optional[date]:
    """
    Get the nth occurrence of a weekday in a given month.

    Args:
        year: The year
        month: The month (1-12)
        weekday: Day of week (0=Monday, 6=Sunday)
        occurrence: Which occurrence (1=1st, 2=2nd, 3=3rd, 4=4th)

    Returns:
        The date of the nth weekday, or None if it doesn't exist (e.g., 5th Tuesday)
    """
    # Get the first day of the month
    first_day = date(year, month, 1)

    # Find the first occurrence of the weekday
    days_until_weekday = (weekday - first_day.weekday()) % 7
    first_occurrence = first_day + timedelta(days=days_until_weekday)

    # Calculate the nth occurrence
    target_date = first_occurrence + timedelta(weeks=(occurrence - 1))

    # Verify it's still in the same month
    if target_date.month != month:
        return None

    return target_date


def get_next_nth_weekday(weekday: int, occurrence: int, from_date: date = None) -> date:
    """
    Get the next occurrence of an nth weekday pattern from a given date.

    Args:
        weekday: Day of week (0=Monday, 6=Sunday)
        occurrence: Which occurrence (1=1st, 2=2nd, 3=3rd, 4=4th)
        from_date: Starting date (defaults to today)

    Returns:
        The next date matching the pattern
    """
    if from_date is None:
        from_date = date.today()

    # Check this month first
    this_month_date = get_nth_weekday_of_month(from_date.year, from_date.month, weekday, occurrence)

    if this_month_date and this_month_date > from_date:
        return this_month_date

    # Move to next month
    if from_date.month == 12:
        next_year = from_date.year + 1
        next_month = 1
    else:
        next_year = from_date.year
        next_month = from_date.month + 1

    return get_nth_weekday_of_month(next_year, next_month, weekday, occurrence)


def get_next_scheduled_check_date(schedule_config: dict, from_date: date = None) -> Optional[date]:
    """
    Calculate the next scheduled check date based on configuration.

    Args:
        schedule_config: Schedule configuration dict with either:
            - {"type": "day_of_month", "days": [1, 15]}
            - {"type": "weekday_pattern", "patterns": [{"weekday": 2, "occurrence": 1}, {"weekday": 2, "occurrence": 3}]}
        from_date: Starting date (defaults to today)

    Returns:
        The next scheduled check date
    """
    if from_date is None:
        from_date = date.today()

    schedule_type = schedule_config.get('type', 'day_of_month')

    if schedule_type == 'day_of_month':
        # Original behavior - specific days of month
        days = schedule_config.get('days', [1, 15])
        if not days:
            return None

        sorted_days = sorted(days)
        current_day = from_date.day

        # Find next day this month
        for day in sorted_days:
            if day > current_day:
                # Check if day is valid for this month
                _, last_day = calendar.monthrange(from_date.year, from_date.month)
                if day <= last_day:
                    return date(from_date.year, from_date.month, day)

        # Move to next month
        if from_date.month == 12:
            next_year = from_date.year + 1
            next_month = 1
        else:
            next_year = from_date.year
            next_month = from_date.month + 1

        # Return first valid day next month
        _, last_day = calendar.monthrange(next_year, next_month)
        for day in sorted_days:
            if day <= last_day:
                return date(next_year, next_month, day)

        return None

    elif schedule_type == 'weekday_pattern':
        # New behavior - nth weekday of month
        patterns = schedule_config.get('patterns', [])
        if not patterns:
            return None

        # Find next occurrence for each pattern
        next_dates = []
        for pattern in patterns:
            weekday = pattern.get('weekday', 0)
            occurrence = pattern.get('occurrence', 1)
            next_date = get_next_nth_weekday(weekday, occurrence, from_date)
            if next_date:
                next_dates.append(next_date)

        if not next_dates:
            return None

        return min(next_dates)

    return None


def format_schedule_description(schedule_config: dict) -> str:
    """
    Format a schedule configuration into a human-readable description.

    Args:
        schedule_config: Schedule configuration dict

    Returns:
        Human-readable description (e.g., "1st and 3rd Tuesday" or "Day 1 and 15")
    """
    schedule_type = schedule_config.get('type', 'day_of_month')

    if schedule_type == 'day_of_month':
        days = schedule_config.get('days', [1, 15])
        if len(days) == 1:
            return f"Day {days[0]} of each month"
        else:
            day_strs = [str(d) for d in sorted(days)]
            return f"Days {', '.join(day_strs[:-1])} and {day_strs[-1]} of each month"

    elif schedule_type == 'weekday_pattern':
        patterns = schedule_config.get('patterns', [])
        if not patterns:
            return "No schedule configured"

        occurrence_names = {1: '1st', 2: '2nd', 3: '3rd', 4: '4th'}

        descriptions = []
        for pattern in patterns:
            weekday = pattern.get('weekday', 0)
            occurrence = pattern.get('occurrence', 1)
            occ_name = occurrence_names.get(occurrence, f'{occurrence}th')
            day_name = WEEKDAY_NAMES[weekday] if 0 <= weekday <= 6 else 'Unknown'
            descriptions.append(f"{occ_name} {day_name}")

        if len(descriptions) == 1:
            return f"{descriptions[0]} of each month"
        else:
            return f"{', '.join(descriptions[:-1])} and {descriptions[-1]} of each month"

    return "Unknown schedule type"


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


class ComplianceChecker:
    """
    Handles automated compliance checking for CIP-010.
    
    This runs on scheduled days and:
    1. Checks all assets for baseline changes
    2. Updates days_in_state counters
    3. Generates aggregate and per-asset reports
    4. Puts detected changes into investigation state
    """
    
    def __init__(self, db_session_factory, email_service: EmailService = None):
        """
        Initialize the compliance checker.

        Args:
            db_session_factory: Callable that returns a database session
            email_service: Optional email service for sending alerts
        """
        self.db_session_factory = db_session_factory
        self.email_service = email_service
    
    def run_scheduled_check(self, trigger_type: str = "scheduled", triggered_by: str = None) -> dict:
        """
        Run a scheduled compliance check.

        Args:
            trigger_type: 'scheduled' for auto checks, 'manual' for user-initiated
            triggered_by: Username if manual trigger

        Returns:
            Dict with check results
        """
        from database import (
            Asset, AssetState, BaselineSnapshot, Change, ChangeStatus,
            ScheduledCheck, CheckStatus, Report, ReportType, AuditLog
        )

        logger.info(f"Starting compliance check (trigger: {trigger_type}, by: {triggered_by or 'system'})")
        check_date = date.today()

        db = self.db_session_factory()
        try:
            # Create scheduled check record
            scheduled_check = ScheduledCheck(
                scheduled_date=check_date,
                executed_at=datetime.utcnow(),
                status=CheckStatus.PENDING,
                trigger_type=trigger_type,
                triggered_by=triggered_by
            )
            db.add(scheduled_check)
            db.flush()
            
            # Get all active assets
            assets = db.query(Asset).filter(
                Asset.current_state != AssetState.RETIRED
            ).all()
            
            results = {
                "check_id": scheduled_check.id,
                "check_date": check_date.isoformat(),
                "assets_checked": 0,
                "assets_unchanged": 0,
                "changes_detected": 0,
                "assets_in_investigation": 0,
                "changes_approaching_deadline": 0,  # v4.0.0: per-change timers
                "changes_past_deadline": 0,  # v4.0.0: per-change timers
                "per_asset_results": []
            }

            for asset in assets:
                asset_result = self._check_asset(db, asset)
                results["per_asset_results"].append(asset_result)
                results["assets_checked"] += 1

                if asset_result["changes_detected"] == 0:
                    results["assets_unchanged"] += 1
                else:
                    results["changes_detected"] += asset_result["changes_detected"]

                if asset_result["in_investigation"]:
                    results["assets_in_investigation"] += 1

                # v4.0.0: Accumulate per-change timer counts
                if asset_result.get("changes_approaching"):
                    results["changes_approaching_deadline"] += asset_result["changes_approaching"]

                if asset_result.get("changes_failed"):
                    results["changes_past_deadline"] += asset_result["changes_failed"]
            
            # Build investigated assets list with reasons
            investigated_assets = []
            for ar in results["per_asset_results"]:
                if ar["in_investigation"] or ar["changes_detected"] > 0:
                    reason = "existing_investigation" if ar["in_investigation"] and ar["new_changes_found"] == 0 else "new_changes"
                    investigated_assets.append({
                        "asset_id": ar["asset_id"],
                        "asset_name": ar["asset_name"],
                        "group_id": ar["group_id"],
                        "reason": reason,
                        "changes": ar.get("changed_fields", []),
                        "pending_changes": ar.get("pending_changes", 0),
                        "new_changes_found": ar.get("new_changes_found", 0),
                        "approaching_deadline": ar.get("approaching_deadline", False),
                        "past_deadline": ar.get("past_deadline", False)
                    })

            # Update scheduled check record
            scheduled_check.status = CheckStatus.COMPLETED
            scheduled_check.assets_checked = results["assets_checked"]
            scheduled_check.changes_detected = results["changes_detected"]
            scheduled_check.assets_unchanged = results["assets_unchanged"]
            scheduled_check.assets_in_investigation = results["assets_in_investigation"]
            scheduled_check.investigated_assets_json = json.dumps(investigated_assets) if investigated_assets else None

            # Add to results for return
            results["investigated_assets"] = investigated_assets
            results["trigger_type"] = trigger_type
            results["triggered_by"] = triggered_by

            # Generate reports
            aggregate_report = self._generate_aggregate_report(results)
            per_asset_reports = self._generate_per_asset_reports(results)
            
            # Save aggregate report
            report = Report(
                report_type=ReportType.SCHEDULED_AGGREGATE,
                title=f"Scheduled Compliance Check - {check_date}",
                report_content=aggregate_report,
                generated_by="system",
                related_assets=json.dumps([r["asset_id"] for r in results["per_asset_results"]]),
                scheduled_check_id=scheduled_check.id
            )
            db.add(report)
            db.flush()
            scheduled_check.aggregate_report_id = report.id
            
            # Create audit log entry
            audit = AuditLog(
                action="scheduled_check",
                action_detail=f"Checked {results['assets_checked']} assets, {results['changes_detected']} changes detected",
                details_json=json.dumps({"summary": results})
            )
            db.add(audit)

            # Send syslog event
            _send_syslog_event(
                action="scheduled_check",
                message=f"CIP-010 compliance check: {results['assets_checked']} assets checked, {results['changes_detected']} changes detected",
                username="system",
                details={
                    "trigger_type": trigger_type,
                    "triggered_by": triggered_by,
                    "assets_checked": results['assets_checked'],
                    "changes_detected": results['changes_detected']
                }
            )

            db.commit()

            logger.info(f"Scheduled check completed: {results['assets_checked']} assets, {results['changes_detected']} changes")

            # Send email alerts if enabled
            self._send_compliance_alerts(results)

            return results
            
        except Exception as e:
            logger.error(f"Error during scheduled check: {e}")
            db.rollback()
            
            # Update check status to failed
            if scheduled_check.id:
                scheduled_check.status = CheckStatus.FAILED
                scheduled_check.error_message = str(e)
                db.commit()
            
            raise
        finally:
            db.close()
    
    def _check_asset(self, db, asset) -> dict:
        """
        Check a single asset for compliance.

        Compares the latest snapshot against the approved baseline.
        If changes are detected, opens an investigation automatically.
        """
        from database import Change, ChangeStatus, AssetState, BaselineSnapshot, AuditLog
        from core import compare_configurations

        result = {
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "group_id": asset.group_id,
            "current_state": asset.current_state.value,
            "days_in_state": 0,
            "changes_detected": 0,
            "new_changes_found": 0,
            "pending_changes": 0,
            "in_investigation": False,
            "approaching_deadline": False,
            "past_deadline": False,
            "compliance_status": "compliant",
            "changed_fields": []
        }

        # Update days in state
        asset.update_days_in_state()
        result["days_in_state"] = asset.days_in_current_state

        # Get approved baseline
        approved_baseline = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.is_current_baseline == True
        ).first()

        if not approved_baseline:
            # No approved baseline - skip this asset
            result["compliance_status"] = "no_baseline"
            return result

        # Get latest UPLOADED snapshot (not a field_merge) that's newer than the baseline
        # We only want to detect changes from newly uploaded configs, not from old merge artifacts
        latest_snapshot = db.query(BaselineSnapshot).filter(
            BaselineSnapshot.asset_id == asset.id,
            BaselineSnapshot.id != approved_baseline.id,
            BaselineSnapshot.source != "field_merge",  # Only uploaded configs, not merge artifacts
            BaselineSnapshot.captured_at > approved_baseline.captured_at  # Must be newer than baseline
        ).order_by(BaselineSnapshot.captured_at.desc()).first()

        # Compare latest snapshot to approved baseline
        if latest_snapshot:
            old_config = json.loads(approved_baseline.config_json)
            new_config = json.loads(latest_snapshot.config_json)

            comparison = compare_configurations(old_config, new_config)

            if not comparison.is_identical:
                # Changes detected! Create change records and open investigation
                result["new_changes_found"] = len(comparison.changes)
                result["changes_detected"] = len(comparison.changes)

                for change in comparison.changes:
                    # Check if this change already exists
                    existing = db.query(Change).filter(
                        Change.asset_id == asset.id,
                        Change.field_path == change.path,
                        Change.new_snapshot_id == latest_snapshot.id
                    ).first()

                    if not existing:
                        change_record = Change(
                            asset_id=asset.id,
                            field_path=change.path,
                            change_type=change.change_type.value,
                            old_value=json.dumps(change.old_value) if change.old_value is not None else None,
                            new_value=json.dumps(change.new_value) if change.new_value is not None else None,
                            items_added=json.dumps(change.items_added) if change.items_added else None,
                            items_removed=json.dumps(change.items_removed) if change.items_removed else None,
                            status=ChangeStatus.PENDING,  # Changes start as PENDING
                            change_signature=change.signature,
                            old_snapshot_id=approved_baseline.id,
                            new_snapshot_id=latest_snapshot.id,
                            compliance_due_date=(datetime.utcnow() + timedelta(days=settings.COMPLIANCE_WINDOW_DAYS)).date()
                        )
                        db.add(change_record)
                        result["changed_fields"].append(change.path)

                # Asset stays COMPLIANT with pending changes - timer started per-change on detection (v4.0.0)
                result["compliance_status"] = "pending_review"

                # Audit log
                audit = AuditLog(
                    action="changes_detected",
                    action_detail=f"CIP-010 check found {len(comparison.changes)} new changes pending review",
                    asset_id=asset.id
                )
                db.add(audit)

                # Send syslog event
                _send_syslog_event(
                    action="changes_detected",
                    message=f"CIP-010 check found {len(comparison.changes)} new changes pending review",
                    asset_id=asset.id,
                    asset_name=asset.asset_name,
                    username="system",
                    details={"changes_count": len(comparison.changes), "fields": result["changed_fields"]}
                )

        # Count all pending/investigation/failed changes (v4.0.0: includes FAILED status)
        unresolved_changes = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION, ChangeStatus.FAILED])
        ).all()

        result["pending_changes"] = len([c for c in unresolved_changes if c.status in [ChangeStatus.PENDING, ChangeStatus.INVESTIGATION]])

        # Check for investigation state
        investigation_changes = [c for c in unresolved_changes if c.status == ChangeStatus.INVESTIGATION]
        if investigation_changes:
            result["in_investigation"] = True
            # Update investigation days
            for change in investigation_changes:
                change.update_investigation_days()

        # v4.0.0: Per-change compliance timer checks
        today = date.today()
        changes_approaching = 0
        changes_failed = 0
        min_days_remaining = None

        for change in unresolved_changes:
            if change.status == ChangeStatus.FAILED:
                changes_failed += 1
                continue

            if change.compliance_due_date:
                days_remaining = (change.compliance_due_date - today).days

                if days_remaining <= 0:
                    # Timer expired - mark change as FAILED
                    change.status = ChangeStatus.FAILED
                    change.status_changed_at = datetime.utcnow()
                    change.status_changed_by = "system"
                    changes_failed += 1
                    logger.info(f"Change {change.id} on asset {asset.asset_name} marked FAILED (timer expired)")
                elif days_remaining <= 5:  # Warning threshold
                    changes_approaching += 1
                    if min_days_remaining is None or days_remaining < min_days_remaining:
                        min_days_remaining = days_remaining
                else:
                    if min_days_remaining is None or days_remaining < min_days_remaining:
                        min_days_remaining = days_remaining

        # Update result with per-change timer info
        if changes_failed > 0:
            result["past_deadline"] = True
            result["changes_failed"] = changes_failed
        if changes_approaching > 0:
            result["approaching_deadline"] = True
            result["changes_approaching"] = changes_approaching
        if min_days_remaining is not None:
            result["days_remaining"] = min_days_remaining

        # Derive asset state from changes (v4.0.0)
        failed_changes = db.query(Change).filter(
            Change.asset_id == asset.id,
            Change.status == ChangeStatus.FAILED
        ).count()

        if failed_changes > 0:
            result["compliance_status"] = "failed"
            if asset.current_state != AssetState.FAILED:
                asset.current_state = AssetState.FAILED
                asset.state_changed_at = datetime.utcnow()
        elif investigation_changes:
            result["compliance_status"] = "investigation"
            if asset.current_state != AssetState.INVESTIGATION:
                asset.current_state = AssetState.INVESTIGATION
                asset.state_changed_at = datetime.utcnow()
        elif result["pending_changes"] > 0:
            result["compliance_status"] = "pending_review"
        elif changes_approaching > 0:
            result["compliance_status"] = "warning"

        # Update last check time
        asset.last_baseline_check = datetime.utcnow()

        return result
    
    def _generate_aggregate_report(self, results: dict) -> str:
        """Generate aggregate compliance report."""
        lines = [
            "=" * 70,
            "CIP-010 SCHEDULED COMPLIANCE CHECK - AGGREGATE REPORT",
            f"CIP-010 Baseline Engine v{settings.APP_VERSION}",
            "=" * 70,
            "",
            f"Check Date:        {results['check_date']}",
            f"Generated:         {datetime.utcnow().isoformat()}",
            "",
            "-" * 40,
            "SUMMARY",
            "-" * 40,
            f"Total Assets Checked:      {results['assets_checked']}",
            f"Assets Unchanged:          {results['assets_unchanged']}",
            f"Total Changes Detected:    {results['changes_detected']}",
            f"Assets in Investigation:   {results['assets_in_investigation']}",
            f"Changes Approaching Deadline: {results.get('changes_approaching_deadline', 0)}",
            f"Changes Past Deadline (FAILED): {results.get('changes_past_deadline', 0)}",
            "",
        ]
        
        # Group by compliance status
        compliant = [r for r in results["per_asset_results"] if r["compliance_status"] == "compliant"]
        warning = [r for r in results["per_asset_results"] if r["compliance_status"] == "warning"]
        failed = [r for r in results["per_asset_results"] if r["compliance_status"] == "failed"]
        
        if failed:
            lines.extend([
                "-" * 40,
                "⚠️  ASSETS REQUIRING IMMEDIATE ATTENTION",
                "-" * 40,
            ])
            for r in failed:
                lines.append(f"  • {r['asset_name']} - {r['days_in_state']} days in {r['current_state']} state")
            lines.append("")
        
        if warning:
            lines.extend([
                "-" * 40,
                "⏰ ASSETS APPROACHING COMPLIANCE DEADLINE",
                "-" * 40,
            ])
            for r in warning:
                lines.append(f"  • {r['asset_name']} - {r['pending_changes']} pending changes")
            lines.append("")
        
        lines.extend([
            "=" * 70,
            "END OF AGGREGATE REPORT",
            "=" * 70,
        ])
        
        return "\n".join(lines)
    
    def _generate_per_asset_reports(self, results: dict) -> list:
        """Generate individual asset reports for assets with changes."""
        reports = []
        
        for asset_result in results["per_asset_results"]:
            if asset_result["pending_changes"] > 0 or asset_result["compliance_status"] != "compliant":
                report = self._generate_single_asset_report(asset_result)
                reports.append({
                    "asset_id": asset_result["asset_id"],
                    "asset_name": asset_result["asset_name"],
                    "content": report
                })
        
        return reports
    
    def _generate_single_asset_report(self, asset_result: dict) -> str:
        """Generate report for a single asset."""
        lines = [
            "=" * 60,
            f"CIP-010 ASSET COMPLIANCE REPORT",
            "=" * 60,
            "",
            f"Asset:             {asset_result['asset_name']}",
            f"Asset ID:          {asset_result['asset_id']}",
            f"Group:             {asset_result['group_id'] or 'Unassigned'}",
            f"Current State:     {asset_result['current_state']}",
            f"Days in State:     {asset_result['days_in_state']}",
            f"Compliance Status: {asset_result['compliance_status'].upper()}",
            "",
            f"Pending Changes:   {asset_result['pending_changes']}",
            f"In Investigation:  {'Yes' if asset_result['in_investigation'] else 'No'}",
            "",
        ]
        
        if asset_result["compliance_status"] == "failed":
            lines.extend([
                "⚠️  COMPLIANCE FAILURE",
                "This asset has exceeded the 35-day baseline verification window.",
                "Immediate action required.",
                "",
            ])
        
        lines.extend([
            "=" * 60,
            "END OF ASSET REPORT",
            "=" * 60,
        ])
        
        return "\n".join(lines)
    
    def _send_compliance_alerts(self, results: dict):
        """Send email alerts based on compliance check results."""
        if not self.email_service or not self.email_service.is_enabled():
            logger.debug("Email notifications disabled - skipping alerts")
            return

        db = self.db_session_factory()
        try:
            from database import Asset, Group

            # Collect assets approaching deadline (warning status)
            approaching_assets = []
            for r in results["per_asset_results"]:
                if r.get("approaching_deadline") and r.get("days_remaining"):
                    asset = db.query(Asset).filter(Asset.id == r["asset_id"]).first()
                    if asset:
                        group = db.query(Group).filter(Group.id == asset.group_id).first()
                        approaching_assets.append({
                            "asset_name": r["asset_name"],
                            "group_name": group.name if group else "Unassigned",
                            "days_remaining": r.get("days_remaining"),
                            "compliance_due_date": asset.compliance_due_date.isoformat() if asset.compliance_due_date else "N/A"
                        })

            # Collect assets that are past deadline (failed)
            failed_assets = []
            for r in results["per_asset_results"]:
                if r.get("past_deadline") or r.get("compliance_status") == "failed":
                    asset = db.query(Asset).filter(Asset.id == r["asset_id"]).first()
                    if asset:
                        group = db.query(Group).filter(Group.id == asset.group_id).first()
                        failed_assets.append({
                            "asset_name": r["asset_name"],
                            "group_name": group.name if group else "Unassigned",
                            "days_remaining": r.get("days_remaining", 0),
                            "compliance_due_date": asset.compliance_due_date.isoformat() if asset.compliance_due_date else "N/A"
                        })

            # Send approaching deadline alert
            if approaching_assets:
                result = self.email_service.send_approaching_deadline_alert(approaching_assets)
                if result["success"]:
                    logger.info(f"Sent approaching deadline alert for {len(approaching_assets)} assets")
                else:
                    logger.warning(f"Failed to send approaching deadline alert: {result['message']}")

            # Send failed deadline alert
            if failed_assets:
                result = self.email_service.send_failed_deadline_alert(failed_assets)
                if result["success"]:
                    logger.info(f"Sent failed deadline alert for {len(failed_assets)} assets")
                else:
                    logger.warning(f"Failed to send failed deadline alert: {result['message']}")

        except Exception as e:
            logger.error(f"Error sending compliance alerts: {e}")
        finally:
            db.close()

    def update_all_state_counters(self):
        """Update days_in_state for all assets and changes."""
        from database import Asset, Change, ChangeStatus

        db = self.db_session_factory()
        try:
            # Update assets
            assets = db.query(Asset).all()
            for asset in assets:
                asset.update_days_in_state()

            # Update investigation changes
            changes = db.query(Change).filter(
                Change.status == ChangeStatus.INVESTIGATION
            ).all()
            for change in changes:
                change.update_investigation_days()

            db.commit()
            logger.info(f"Updated state counters for {len(assets)} assets and {len(changes)} changes")

        finally:
            db.close()


class FolderScanner:
    """
    Scans a folder for new baseline JSON files and processes them.
    """

    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.processed_files = set()  # Track processed files to avoid duplicates
        self.last_scan_result = None

    def scan_folder(self, folder_path: str) -> dict:
        """
        Scan a folder for JSON files and process new ones.

        Args:
            folder_path: Path to the folder to scan

        Returns:
            Dict with scan results
        """
        from database import Asset, AssetState, BaselineSnapshot, Change, ChangeStatus, AuditLog
        from core import compare_configurations, compute_config_hash, parse_json_content

        folder = Path(folder_path)
        if not folder.exists():
            raise FileNotFoundError(f"Folder not found: {folder_path}")

        if not folder.is_dir():
            raise ValueError(f"Path is not a directory: {folder_path}")

        result = {
            "scan_time": datetime.utcnow().isoformat(),
            "folder_path": folder_path,
            "files_found": 0,
            "files_processed": 0,
            "files_skipped": 0,
            "new_assets": 0,
            "updated_assets": 0,
            "errors": []
        }

        db = self.db_session_factory()
        try:
            # Find all JSON files in the folder
            json_files = list(folder.glob("*.json"))
            result["files_found"] = len(json_files)

            for json_file in json_files:
                file_key = f"{json_file.name}_{json_file.stat().st_mtime}"

                # Skip if already processed
                if file_key in self.processed_files:
                    result["files_skipped"] += 1
                    continue

                try:
                    # Read and parse the file
                    content = json_file.read_text(encoding='utf-8')
                    parsed = parse_json_content(content, json_file.name)

                    if not parsed:
                        result["errors"].append(f"{json_file.name}: Failed to parse JSON")
                        continue

                    if not parsed.fqdn:
                        result["errors"].append(f"{json_file.name}: No FQDN found in file")
                        continue

                    asset_identifier = parsed.fqdn

                    # Check if asset exists
                    asset = db.query(Asset).filter(Asset.asset_name == asset_identifier).first()

                    if not asset:
                        # New asset - check for group in config
                        group_id = parsed.config.get("group") if parsed.config else None

                        asset = Asset(
                            asset_name=asset_identifier,
                            fqdn=parsed.fqdn,
                            version=parsed.version,
                            group_id=group_id,
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
                            source="folder_scan",
                            triggered_by="system",
                            filename=json_file.name,
                            is_current_baseline=False,
                            promoted_at=None,
                            promoted_by=None
                        )
                        db.add(snapshot)

                        # Audit log
                        audit = AuditLog(
                            action="folder_scan_new_asset",
                            action_detail=f"Created new asset from folder scan: {asset_identifier}"
                        )
                        db.add(audit)

                        # Send syslog event
                        _send_syslog_event(
                            action="folder_scan_new_asset",
                            message=f"Created new asset from folder scan: {asset_identifier}",
                            asset_id=asset.id,
                            asset_name=asset.asset_name,
                            username="system",
                            details={"filename": json_file.name}
                        )

                        result["new_assets"] += 1
                        logger.info(f"Folder scan: New asset created - {asset_identifier}")
                    else:
                        # Existing asset - compare with current baseline
                        current_baseline = db.query(BaselineSnapshot).filter(
                            BaselineSnapshot.asset_id == asset.id,
                            BaselineSnapshot.is_current_baseline == True
                        ).first()

                        if current_baseline:
                            # Check timestamp
                            baseline_timestamp = current_baseline.capture_timestamp or current_baseline.promoted_at or current_baseline.captured_at
                            new_timestamp = parsed.capture_timestamp

                            if new_timestamp and baseline_timestamp and new_timestamp <= baseline_timestamp:
                                result["files_skipped"] += 1
                                self.processed_files.add(file_key)
                                continue

                            # Compare configurations
                            old_config = json.loads(current_baseline.config_json)
                            comparison = compare_configurations(old_config, parsed.config)

                            if not comparison.is_identical:
                                # Create new snapshot
                                new_snapshot = BaselineSnapshot(
                                    asset_id=asset.id,
                                    config_json=json.dumps(parsed.config),
                                    config_hash=comparison.new_hash,
                                    capture_timestamp=parsed.capture_timestamp,
                                    source="folder_scan",
                                    triggered_by="system",
                                    filename=json_file.name,
                                    is_current_baseline=False
                                )
                                db.add(new_snapshot)
                                db.flush()

                                # Create change records
                                for change in comparison.changes:
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
                                        new_snapshot_id=new_snapshot.id
                                    )
                                    db.add(change_record)

                                # Audit log
                                audit = AuditLog(
                                    action="folder_scan_changes",
                                    action_detail=f"Folder scan detected {len(comparison.changes)} changes for {asset_identifier}"
                                )
                                db.add(audit)

                                # Send syslog event
                                _send_syslog_event(
                                    action="folder_scan_changes",
                                    message=f"Folder scan detected {len(comparison.changes)} changes for {asset_identifier}",
                                    asset_id=asset.id,
                                    asset_name=asset.asset_name,
                                    username="system",
                                    details={"changes_count": len(comparison.changes), "filename": json_file.name}
                                )

                                result["updated_assets"] += 1
                                logger.info(f"Folder scan: {len(comparison.changes)} changes detected for {asset_identifier}")

                        # Update metadata
                        asset.fqdn = parsed.fqdn or asset.fqdn
                        asset.version = parsed.version or asset.version
                        asset.updated_at = datetime.utcnow()

                    result["files_processed"] += 1
                    self.processed_files.add(file_key)

                except Exception as e:
                    result["errors"].append(f"{json_file.name}: {str(e)}")
                    logger.error(f"Error processing {json_file.name}: {e}")

            db.commit()
            self.last_scan_result = result
            logger.info(f"Folder scan completed: {result['files_processed']} files processed, {result['new_assets']} new assets, {result['updated_assets']} updated")

            return result

        except Exception as e:
            logger.error(f"Folder scan error: {e}")
            db.rollback()
            raise
        finally:
            db.close()


class SchedulerService:
    """
    Manages scheduled tasks for compliance checking and folder scanning.
    """

    def __init__(self, db_session_factory):
        """
        Initialize the scheduler service.

        Args:
            db_session_factory: Callable that returns a database session
        """
        self.db_session_factory = db_session_factory
        self.scheduler = BackgroundScheduler()
        self.email_service = EmailService(db_session_factory)
        self.checker = ComplianceChecker(db_session_factory, self.email_service)
        self.folder_scanner = FolderScanner(db_session_factory)
        self._running = False
        self._watch_folder = None
    
    def start(self):
        """Start the scheduler."""
        if self._running:
            logger.warning("Scheduler already running")
            return

        # Load and schedule compliance checks from database settings
        self._load_compliance_schedule_from_db()

        # Daily job to update state counters
        self.scheduler.add_job(
            self.checker.update_all_state_counters,
            trigger=CronTrigger(hour=1, minute=0),
            id="daily_state_update",
            name="Daily State Counter Update",
            replace_existing=True
        )

        # Check for configured watch folder in database and start scanning
        self._load_watch_folder_from_db()

        # Load weekly email report schedule
        self._load_weekly_report_schedule()

        self.scheduler.start()
        self._running = True
        logger.info("Scheduler service started")

    def _load_compliance_schedule_from_db(self):
        """Load compliance check schedule from database settings."""
        from database import SystemSetting

        db = self.db_session_factory()
        try:
            # Get settings
            enabled_setting = db.query(SystemSetting).filter(SystemSetting.key == "compliance_check_enabled").first()
            type_setting = db.query(SystemSetting).filter(SystemSetting.key == "compliance_check_type").first()
            days_setting = db.query(SystemSetting).filter(SystemSetting.key == "compliance_check_days").first()
            patterns_setting = db.query(SystemSetting).filter(SystemSetting.key == "compliance_check_patterns").first()
            hour_setting = db.query(SystemSetting).filter(SystemSetting.key == "compliance_check_hour").first()
            minute_setting = db.query(SystemSetting).filter(SystemSetting.key == "compliance_check_minute").first()

            # Defaults
            enabled = (enabled_setting.value if enabled_setting else 'true').lower() == 'true'
            schedule_type = type_setting.value if type_setting else 'day_of_month'
            days_str = days_setting.value if days_setting else '1,15'
            patterns_json = patterns_setting.value if patterns_setting else '[]'
            hour = int(hour_setting.value) if hour_setting and hour_setting.value else 2
            minute = int(minute_setting.value) if minute_setting and minute_setting.value else 0

            # Remove existing compliance check jobs
            for job in self.scheduler.get_jobs():
                if job.id.startswith('compliance_check_'):
                    self.scheduler.remove_job(job.id)

            if not enabled:
                logger.info("Compliance checks disabled")
                return

            if schedule_type == 'weekday_pattern':
                # New behavior - nth weekday of month (e.g., 1st and 3rd Tuesday)
                try:
                    patterns = json.loads(patterns_json) if patterns_json else []
                except json.JSONDecodeError:
                    patterns = []

                if not patterns:
                    logger.warning("No weekday patterns configured, using defaults")
                    patterns = [{"weekday": 1, "occurrence": 1}, {"weekday": 1, "occurrence": 3}]  # 1st & 3rd Tuesday

                for i, pattern in enumerate(patterns):
                    weekday = pattern.get('weekday', 0)
                    occurrence = pattern.get('occurrence', 1)

                    # APScheduler uses different weekday notation
                    # CronTrigger day_of_week: 'mon', 'tue', etc. and week: 1-5 for nth occurrence
                    # We need to use a custom approach - schedule daily and check if it's the right day
                    # OR use the 'day_of_week' with specific day calculation

                    # For nth weekday, we'll schedule to run daily at the specified time
                    # and check in the job if today matches the pattern
                    # This is simpler and more reliable than complex cron expressions

                    occurrence_names = {1: '1st', 2: '2nd', 3: '3rd', 4: '4th'}
                    occ_name = occurrence_names.get(occurrence, f'{occurrence}th')
                    day_name = WEEKDAY_NAMES[weekday] if 0 <= weekday <= 6 else 'Unknown'

                    self.scheduler.add_job(
                        self._run_weekday_pattern_check,
                        trigger=CronTrigger(hour=hour, minute=minute),  # Run daily at specified time
                        id=f"compliance_check_weekday_{weekday}_{occurrence}",
                        name=f"CIP-010 Compliance Check - {occ_name} {day_name}",
                        kwargs={'weekday': weekday, 'occurrence': occurrence},
                        replace_existing=True
                    )
                    logger.info(f"Scheduled compliance check for {occ_name} {day_name} at {hour:02d}:{minute:02d}")

            else:
                # Original behavior - specific days of month
                check_days = [int(d.strip()) for d in days_str.split(',') if d.strip()]

                for day in check_days:
                    trigger = CronTrigger(day=day, hour=hour, minute=minute)
                    self.scheduler.add_job(
                        self.checker.run_scheduled_check,
                        trigger=trigger,
                        id=f"compliance_check_day_{day}",
                        name=f"CIP-010 Compliance Check - Day {day}",
                        replace_existing=True
                    )
                    logger.info(f"Scheduled compliance check for day {day} at {hour:02d}:{minute:02d}")

        except Exception as e:
            logger.error(f"Error loading compliance schedule: {e}")
            # Fall back to defaults
            for day in settings.SCHEDULED_CHECK_DAYS:
                trigger = CronTrigger(day=day, hour=2, minute=0)
                self.scheduler.add_job(
                    self.checker.run_scheduled_check,
                    trigger=trigger,
                    id=f"compliance_check_day_{day}",
                    name=f"CIP-010 Compliance Check - Day {day}",
                    replace_existing=True
                )
        finally:
            db.close()

    def _run_weekday_pattern_check(self, weekday: int, occurrence: int):
        """
        Run compliance check if today matches the weekday pattern.

        This is called daily and checks if today is the nth weekday of the month.
        """
        today = date.today()
        expected_date = get_nth_weekday_of_month(today.year, today.month, weekday, occurrence)

        if expected_date == today:
            occurrence_names = {1: '1st', 2: '2nd', 3: '3rd', 4: '4th'}
            occ_name = occurrence_names.get(occurrence, f'{occurrence}th')
            day_name = WEEKDAY_NAMES[weekday]
            logger.info(f"Today is the {occ_name} {day_name} - running compliance check")
            self.checker.run_scheduled_check()
        else:
            # Not the right day, skip silently
            pass

    def reload_compliance_schedule(self):
        """Reload compliance check schedule from database (called when settings change)."""
        logger.info("Reloading compliance check schedule...")
        self._load_compliance_schedule_from_db()
        return {"message": "Compliance schedule reloaded", "jobs": self.get_scheduled_jobs()}

    def _load_weekly_report_schedule(self):
        """Load weekly email report schedule from database settings."""
        from database import SystemSetting

        db = self.db_session_factory()
        try:
            # Get settings
            enabled_setting = db.query(SystemSetting).filter(SystemSetting.key == "alert_weekly_enabled").first()
            day_setting = db.query(SystemSetting).filter(SystemSetting.key == "alert_weekly_day").first()
            time_setting = db.query(SystemSetting).filter(SystemSetting.key == "alert_weekly_time").first()

            # Defaults
            enabled = (enabled_setting.value if enabled_setting else 'true').lower() == 'true'
            day_of_week = int(day_setting.value) if day_setting and day_setting.value else 0  # 0 = Monday
            time_str = time_setting.value if time_setting and time_setting.value else '08:00'

            # Parse time
            try:
                hour, minute = map(int, time_str.split(':'))
            except:
                hour, minute = 8, 0

            # Remove existing weekly report job if any
            try:
                self.scheduler.remove_job("weekly_email_report")
            except Exception:
                pass

            if not enabled:
                logger.info("Weekly email reports disabled")
                return

            # Schedule weekly report
            # day_of_week: 0=Monday, 1=Tuesday, etc.
            day_names = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']
            trigger = CronTrigger(
                day_of_week=day_names[day_of_week],
                hour=hour,
                minute=minute
            )
            self.scheduler.add_job(
                self._run_weekly_report,
                trigger=trigger,
                id="weekly_email_report",
                name=f"Weekly Compliance Report - {day_names[day_of_week].capitalize()} {hour:02d}:{minute:02d}",
                replace_existing=True
            )
            logger.info(f"Scheduled weekly email report for {day_names[day_of_week]} at {hour:02d}:{minute:02d}")

        except Exception as e:
            logger.error(f"Error loading weekly report schedule: {e}")
        finally:
            db.close()

    def _run_weekly_report(self):
        """Run weekly email report job."""
        try:
            result = self.email_service.send_weekly_investigation_report()
            if result["success"]:
                logger.info("Weekly compliance report sent successfully")
            else:
                logger.warning(f"Weekly report failed: {result['message']}")
        except Exception as e:
            logger.error(f"Error sending weekly report: {e}")

    def reload_weekly_report_schedule(self):
        """Reload weekly report schedule from database (called when settings change)."""
        logger.info("Reloading weekly report schedule...")
        self._load_weekly_report_schedule()
        return {"message": "Weekly report schedule reloaded", "jobs": self.get_scheduled_jobs()}

    def _load_watch_folder_from_db(self):
        """Load watch folder setting from database and start scanning if configured."""
        from database import SystemSetting

        db = self.db_session_factory()
        try:
            setting = db.query(SystemSetting).filter(SystemSetting.key == "watch_folder_path").first()
            if setting and setting.value:
                self.update_watch_folder(setting.value)
        finally:
            db.close()

    def _run_folder_scan(self):
        """Run folder scan job (called by scheduler)."""
        if self._watch_folder:
            try:
                self.folder_scanner.scan_folder(self._watch_folder)
            except Exception as e:
                logger.error(f"Scheduled folder scan failed: {e}")

    def update_watch_folder(self, folder_path: str):
        """
        Update the watch folder and reschedule the scanning job.

        Args:
            folder_path: Path to the folder to watch
        """
        self._watch_folder = folder_path

        # Remove existing folder scan job if any
        try:
            self.scheduler.remove_job("folder_scan")
        except Exception:
            pass

        if folder_path:
            # Add folder scan job - scan every 5 minutes
            self.scheduler.add_job(
                self._run_folder_scan,
                trigger=IntervalTrigger(minutes=5),
                id="folder_scan",
                name=f"Folder Scan - {folder_path}",
                replace_existing=True
            )
            logger.info(f"Started folder scanning for: {folder_path}")
        else:
            logger.info("Watch folder cleared - folder scanning disabled")

    def scan_folder_now(self, folder_path: str = None) -> dict:
        """
        Manually trigger a folder scan.

        Args:
            folder_path: Optional path override. Uses configured path if not provided.

        Returns:
            Dict with scan results
        """
        path = folder_path or self._watch_folder
        if not path:
            raise ValueError("No watch folder configured")
        return self.folder_scanner.scan_folder(path)

    def get_watch_folder_status(self) -> dict:
        """Get current watch folder status."""
        return {
            "folder_path": self._watch_folder,
            "is_configured": bool(self._watch_folder),
            "last_scan": self.folder_scanner.last_scan_result
        }
    
    def stop(self):
        """Stop the scheduler."""
        if not self._running:
            return
        
        self.scheduler.shutdown(wait=True)
        self._running = False
        logger.info("Scheduler service stopped")
    
    def run_check_now(self, triggered_by: str = None) -> dict:
        """Manually trigger a compliance check."""
        return self.checker.run_scheduled_check(
            trigger_type="manual",
            triggered_by=triggered_by
        )
    
    def get_scheduled_jobs(self) -> list:
        """Get list of scheduled jobs."""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": job.next_run_time.isoformat() if job.next_run_time else None
            })
        return jobs
    
    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._running
