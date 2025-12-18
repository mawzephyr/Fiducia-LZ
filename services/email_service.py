"""
Email notification service for Fiducia CIP-010 Baseline Engine.

Provides SMTP email functionality for compliance alerts:
- Approaching deadline warnings
- Failed/overdue alerts
- Weekly investigation reports
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class EmailService:
    """SMTP email service with configuration caching."""

    def __init__(self, db_session_factory):
        """Initialize email service with database session factory."""
        self.db_session_factory = db_session_factory
        self._config_cache = None
        self._config_cache_time = None
        self._cache_duration = timedelta(seconds=60)

    def _get_setting(self, db: Session, key: str, default: Any = None) -> Any:
        """Get a setting value from the database."""
        from database import SystemSetting
        setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if setting and setting.value is not None:
            return setting.value
        return default

    def _get_smtp_config(self) -> Dict:
        """Get SMTP configuration from database with caching."""
        # Check cache
        if self._config_cache and self._config_cache_time:
            if datetime.utcnow() - self._config_cache_time < self._cache_duration:
                return self._config_cache

        db = self.db_session_factory()
        try:
            config = {
                "smtp_enabled": self._get_setting(db, "smtp_enabled", "false").lower() == "true",
                "smtp_server": self._get_setting(db, "smtp_server", ""),
                "smtp_port": int(self._get_setting(db, "smtp_port", "587")),
                "smtp_use_tls": self._get_setting(db, "smtp_use_tls", "true").lower() == "true",
                "smtp_use_ssl": self._get_setting(db, "smtp_use_ssl", "false").lower() == "true",
                "smtp_username": self._get_setting(db, "smtp_username", ""),
                "smtp_password": self._get_setting(db, "smtp_password", ""),
                "smtp_from_address": self._get_setting(db, "smtp_from_address", ""),
                "smtp_from_name": self._get_setting(db, "smtp_from_name", "Fiducia"),
                "smtp_timeout": int(self._get_setting(db, "smtp_timeout", "30")),
            }

            self._config_cache = config
            self._config_cache_time = datetime.utcnow()
            return config
        except Exception as e:
            logger.error(f"Error getting SMTP config: {e}")
            return {}
        finally:
            db.close()

    def _get_alert_config(self) -> Dict:
        """Get alert configuration from database."""
        db = self.db_session_factory()
        try:
            return {
                "emails_compliance": self._get_setting(db, "alert_emails_compliance", ""),
                "emails_managers": self._get_setting(db, "alert_emails_managers", ""),
                "approaching_enabled": self._get_setting(db, "alert_approaching_enabled", "true").lower() == "true",
                "failed_enabled": self._get_setting(db, "alert_failed_enabled", "true").lower() == "true",
                "weekly_enabled": self._get_setting(db, "alert_weekly_enabled", "true").lower() == "true",
                "weekly_day": int(self._get_setting(db, "alert_weekly_day", "0")),
                "weekly_time": self._get_setting(db, "alert_weekly_time", "08:00"),
            }
        except Exception as e:
            logger.error(f"Error getting alert config: {e}")
            return {}
        finally:
            db.close()

    def _parse_email_list(self, email_string: str) -> List[str]:
        """Parse comma-separated email string into list."""
        if not email_string:
            return []
        return [e.strip() for e in email_string.split(",") if e.strip()]

    def _get_all_recipients(self) -> List[str]:
        """Get combined list of all alert recipients."""
        alert_config = self._get_alert_config()
        compliance = self._parse_email_list(alert_config.get("emails_compliance", ""))
        managers = self._parse_email_list(alert_config.get("emails_managers", ""))
        # Combine and deduplicate
        return list(set(compliance + managers))

    def is_enabled(self) -> bool:
        """Check if email notifications are enabled."""
        config = self._get_smtp_config()
        return config.get("smtp_enabled", False) and bool(config.get("smtp_server"))

    def clear_cache(self):
        """Clear the configuration cache."""
        self._config_cache = None
        self._config_cache_time = None

    def test_connection(self) -> Dict:
        """Test SMTP connection with current settings."""
        config = self._get_smtp_config()

        if not config.get("smtp_server"):
            return {"success": False, "message": "SMTP server not configured"}

        try:
            if config.get("smtp_use_ssl"):
                server = smtplib.SMTP_SSL(
                    config["smtp_server"],
                    config["smtp_port"],
                    timeout=config.get("smtp_timeout", 30)
                )
            else:
                server = smtplib.SMTP(
                    config["smtp_server"],
                    config["smtp_port"],
                    timeout=config.get("smtp_timeout", 30)
                )

                if config.get("smtp_use_tls"):
                    server.starttls()

            if config.get("smtp_username") and config.get("smtp_password"):
                server.login(config["smtp_username"], config["smtp_password"])

            server.quit()
            return {"success": True, "message": "Connection successful"}

        except smtplib.SMTPAuthenticationError as e:
            return {"success": False, "message": f"Authentication failed: {str(e)}"}
        except smtplib.SMTPConnectError as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        html_body: Optional[str] = None
    ) -> Dict:
        """Send an email using configured SMTP settings."""
        if not self.is_enabled():
            return {"success": False, "message": "Email notifications are disabled"}

        if not to:
            return {"success": False, "message": "No recipients specified"}

        config = self._get_smtp_config()

        try:
            # Create message
            if html_body:
                msg = MIMEMultipart("alternative")
                msg.attach(MIMEText(body, "plain"))
                msg.attach(MIMEText(html_body, "html"))
            else:
                msg = MIMEText(body, "plain")

            # Set headers
            from_name = config.get("smtp_from_name", "Fiducia")
            from_addr = config.get("smtp_from_address", "")
            msg["From"] = f"{from_name} <{from_addr}>"
            msg["To"] = ", ".join(to)
            msg["Subject"] = subject

            # Connect and send
            if config.get("smtp_use_ssl"):
                server = smtplib.SMTP_SSL(
                    config["smtp_server"],
                    config["smtp_port"],
                    timeout=config.get("smtp_timeout", 30)
                )
            else:
                server = smtplib.SMTP(
                    config["smtp_server"],
                    config["smtp_port"],
                    timeout=config.get("smtp_timeout", 30)
                )
                if config.get("smtp_use_tls"):
                    server.starttls()

            if config.get("smtp_username") and config.get("smtp_password"):
                server.login(config["smtp_username"], config["smtp_password"])

            server.sendmail(from_addr, to, msg.as_string())
            server.quit()

            logger.info(f"Email sent to {len(to)} recipients: {subject}")
            return {"success": True, "message": f"Email sent to {len(to)} recipients"}

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {"success": False, "message": f"Failed to send: {str(e)}"}

    def send_test_email(self, to: str) -> Dict:
        """Send a test email to verify configuration.

        Note: This bypasses the smtp_enabled check so users can test
        their configuration before enabling notifications.
        """
        config = self._get_smtp_config()

        if not config.get("smtp_server"):
            return {"success": False, "message": "SMTP server not configured"}

        if not to:
            return {"success": False, "message": "No recipient specified"}

        subject = "[Fiducia] Test Email - Configuration Verified"
        body = f"""This is a test email from Fiducia CIP-010 Baseline Engine.

If you received this message, your SMTP configuration is working correctly.

Sent at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

--
Fiducia - Infrastructure Baseline Management
"""

        try:
            # Create message
            msg = MIMEText(body, "plain")
            from_name = config.get("smtp_from_name", "Fiducia")
            from_addr = config.get("smtp_from_address", "")
            msg["From"] = f"{from_name} <{from_addr}>"
            msg["To"] = to
            msg["Subject"] = subject

            # Connect and send
            if config.get("smtp_use_ssl"):
                server = smtplib.SMTP_SSL(
                    config["smtp_server"],
                    config["smtp_port"],
                    timeout=config.get("smtp_timeout", 30)
                )
            else:
                server = smtplib.SMTP(
                    config["smtp_server"],
                    config["smtp_port"],
                    timeout=config.get("smtp_timeout", 30)
                )
                if config.get("smtp_use_tls"):
                    server.starttls()

            if config.get("smtp_username") and config.get("smtp_password"):
                server.login(config["smtp_username"], config["smtp_password"])

            server.sendmail(from_addr, [to], msg.as_string())
            server.quit()

            logger.info(f"Test email sent to {to}")
            return {"success": True, "message": f"Test email sent to {to}"}

        except smtplib.SMTPAuthenticationError as e:
            return {"success": False, "message": f"Authentication failed: {str(e)}"}
        except smtplib.SMTPConnectError as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}
        except Exception as e:
            logger.error(f"Failed to send test email: {e}")
            return {"success": False, "message": f"Failed to send: {str(e)}"}

    def send_approaching_deadline_alert(self, changes: List[Dict]) -> Dict:
        """Send alert for changes approaching compliance deadline (v4.0.0: per-change timers)."""
        alert_config = self._get_alert_config()

        if not alert_config.get("approaching_enabled", True):
            return {"success": False, "message": "Approaching deadline alerts are disabled"}

        recipients = self._get_all_recipients()
        if not recipients:
            return {"success": False, "message": "No alert recipients configured"}

        if not changes:
            return {"success": False, "message": "No changes to report"}

        count = len(changes)
        subject = f"[Fiducia] {count} Change(s) Approaching Compliance Deadline"

        # Build email body
        lines = [
            "COMPLIANCE DEADLINE WARNING",
            "=" * 50,
            "",
            f"The following {count} change(s) are approaching their 30-day compliance deadline:",
            "",
        ]

        for change in changes:
            lines.append(f"  - Asset: {change.get('asset_name', 'Unknown')}")
            lines.append(f"    Field: {change.get('field_path', 'Unknown')}")
            lines.append(f"    Team: {change.get('group_name', 'Unassigned')}")
            lines.append(f"    Days Remaining: {change.get('days_remaining', 'N/A')}")
            lines.append(f"    Deadline: {change.get('compliance_due_date', 'N/A')}")
            lines.append("")

        lines.extend([
            "ACTION REQUIRED:",
            "Review and resolve these changes before the deadline to avoid",
            "non-compliance status and PNCI documentation requirements.",
            "",
            "Log in to Fiducia to review pending changes and approve or reject them.",
            "",
            "--",
            "Fiducia - Infrastructure Baseline Management",
        ])

        body = "\n".join(lines)
        return self.send_email(recipients, subject, body)

    def send_failed_deadline_alert(self, changes: List[Dict]) -> Dict:
        """Send critical alert for changes that have exceeded compliance deadline (v4.0.0: per-change timers)."""
        alert_config = self._get_alert_config()

        if not alert_config.get("failed_enabled", True):
            return {"success": False, "message": "Failed deadline alerts are disabled"}

        recipients = self._get_all_recipients()
        if not recipients:
            return {"success": False, "message": "No alert recipients configured"}

        if not changes:
            return {"success": False, "message": "No changes to report"}

        count = len(changes)
        subject = f"[Fiducia] CRITICAL: {count} Change(s) Exceeded Compliance Deadline"

        # Build email body
        lines = [
            "!!! CRITICAL COMPLIANCE ALERT !!!",
            "=" * 50,
            "",
            f"The following {count} change(s) have EXCEEDED their 30-day compliance deadline:",
            "",
        ]

        for change in changes:
            lines.append(f"  - Asset: {change.get('asset_name', 'Unknown')}")
            lines.append(f"    Field: {change.get('field_path', 'Unknown')}")
            lines.append(f"    Team: {change.get('group_name', 'Unassigned')}")
            lines.append(f"    Deadline Was: {change.get('compliance_due_date', 'N/A')}")
            lines.append(f"    Days Overdue: {abs(change.get('days_overdue', 0))}")
            lines.append("")

        lines.extend([
            "IMMEDIATE ACTION REQUIRED:",
            "",
            "These changes are now in FAILED status per CIP-010 requirements.",
            "The following documentation is required:",
            "",
            "  1. Potential Non-Compliance Identification (PNCI)",
            "  2. Extent of Condition Review",
            "  3. Corrective Action Plan",
            "",
            "Log in to Fiducia immediately to generate PNCI reports and begin remediation.",
            "",
            "--",
            "Fiducia - Infrastructure Baseline Management",
        ])

        body = "\n".join(lines)
        return self.send_email(recipients, subject, body)

    def send_weekly_investigation_report(self) -> Dict:
        """Send weekly summary of compliance investigations (v4.0.0: per-change timers)."""
        alert_config = self._get_alert_config()

        if not alert_config.get("weekly_enabled", True):
            return {"success": False, "message": "Weekly reports are disabled"}

        recipients = self._get_all_recipients()
        if not recipients:
            return {"success": False, "message": "No alert recipients configured"}

        # Get current compliance data
        db = self.db_session_factory()
        try:
            from database import Asset, AssetState, Change, ChangeStatus, Group
            from config import settings

            # Get asset counts
            total_assets = db.query(Asset).filter(
                Asset.current_state != AssetState.RETIRED
            ).count()

            compliant = db.query(Asset).filter(
                Asset.current_state.in_([AssetState.ACTIVE, AssetState.COMPLIANT])
            ).count()

            investigation_assets_count = db.query(Asset).filter(
                Asset.current_state == AssetState.INVESTIGATION
            ).count()

            failed_assets_count = db.query(Asset).filter(
                Asset.current_state == AssetState.FAILED
            ).count()

            # v4.0.0: Get per-change counts
            pending_changes = db.query(Change).filter(
                Change.status == ChangeStatus.PENDING
            ).count()

            investigation_changes = db.query(Change).filter(
                Change.status == ChangeStatus.INVESTIGATION
            ).count()

            failed_changes = db.query(Change).filter(
                Change.status == ChangeStatus.FAILED
            ).count()

            today = datetime.utcnow().date()
            report_date = today.strftime("%Y-%m-%d")

            subject = f"[Fiducia] Weekly Compliance Report - {report_date}"

            # Build report
            lines = [
                "WEEKLY COMPLIANCE STATUS REPORT",
                "=" * 50,
                f"Report Date: {report_date}",
                f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
                "",
                "ASSET SUMMARY",
                "-" * 30,
                f"  Total Assets:        {total_assets}",
                f"  Compliant:           {compliant}",
                f"  In Investigation:    {investigation_assets_count}",
                f"  Failed (Overdue):    {failed_assets_count}",
                "",
                "CHANGE SUMMARY (Per-Change Timers)",
                "-" * 30,
                f"  Pending Changes:     {pending_changes}",
                f"  In Investigation:    {investigation_changes}",
                f"  Failed (Overdue):    {failed_changes}",
                "",
            ]

            # Show changes approaching deadline
            approaching_changes = db.query(Change).filter(
                Change.status.in_([ChangeStatus.PENDING, ChangeStatus.INVESTIGATION]),
                Change.compliance_due_date != None,
                Change.compliance_due_date <= today + timedelta(days=settings.YELLOW_THRESHOLD_DAYS),
                Change.compliance_due_date > today
            ).all()

            if approaching_changes:
                lines.append("CHANGES APPROACHING DEADLINE")
                lines.append("-" * 30)

                for change in approaching_changes:
                    asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
                    asset_name = asset.asset_name if asset else "Unknown"
                    group = db.query(Group).filter(Group.id == asset.group_id).first() if asset else None
                    group_name = group.name if group else "Unassigned"

                    days_remaining = (change.compliance_due_date - today).days
                    if days_remaining <= settings.CRITICAL_THRESHOLD_DAYS:
                        status = "CRITICAL"
                    else:
                        status = "WARNING"

                    lines.append(f"  - {asset_name}: {change.field_path}")
                    lines.append(f"    Team: {group_name}")
                    lines.append(f"    Days Remaining: {days_remaining} ({status})")
                    lines.append("")

            # Show failed changes
            if failed_changes > 0:
                lines.append("FAILED CHANGES REQUIRING ATTENTION")
                lines.append("-" * 30)
                failed_change_records = db.query(Change).filter(
                    Change.status == ChangeStatus.FAILED
                ).all()

                for change in failed_change_records:
                    asset = db.query(Asset).filter(Asset.id == change.asset_id).first()
                    asset_name = asset.asset_name if asset else "Unknown"
                    group = db.query(Group).filter(Group.id == asset.group_id).first() if asset else None
                    group_name = group.name if group else "Unassigned"
                    lines.append(f"  - {asset_name}: {change.field_path} ({group_name})")

                lines.append("")
                lines.append("These changes require PNCI documentation and corrective action.")
                lines.append("")

            lines.extend([
                "--",
                "Log in to Fiducia for full details and to take action.",
                "",
                "Fiducia - Infrastructure Baseline Management",
            ])

            body = "\n".join(lines)
            return self.send_email(recipients, subject, body)

        except Exception as e:
            logger.error(f"Error generating weekly report: {e}")
            return {"success": False, "message": f"Error: {str(e)}"}
        finally:
            db.close()
