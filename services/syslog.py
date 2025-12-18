"""
Syslog Service for Fiducia - RFC 5424 Compliant Remote Logging.

Provides configurable per-event syslog forwarding with protocol support:
- UDP (default, connectionless)
- TCP (reliable, connection-oriented)
- TLS (encrypted, certificate verification optional)
"""

import logging
import socket
import ssl
import json
import os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable
from enum import Enum, IntEnum

logger = logging.getLogger(__name__)


class SyslogFacility(IntEnum):
    """RFC 5424 Facility codes."""
    KERN = 0
    USER = 1
    MAIL = 2
    DAEMON = 3
    AUTH = 4
    SYSLOG = 5
    LPR = 6
    NEWS = 7
    UUCP = 8
    CRON = 9
    AUTHPRIV = 10
    FTP = 11
    NTP = 12
    SECURITY = 13
    CONSOLE = 14
    SOLARIS_CRON = 15
    LOCAL0 = 16
    LOCAL1 = 17
    LOCAL2 = 18
    LOCAL3 = 19
    LOCAL4 = 20
    LOCAL5 = 21
    LOCAL6 = 22
    LOCAL7 = 23


class SyslogSeverity(IntEnum):
    """RFC 5424 Severity codes."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class SyslogProtocol(str, Enum):
    """Supported syslog transport protocols."""
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


# Map audit event types to syslog severity
EVENT_SEVERITY_MAP = {
    # Asset lifecycle events
    "create_asset": SyslogSeverity.INFORMATIONAL,
    "delete_asset": SyslogSeverity.WARNING,
    "rename_asset": SyslogSeverity.INFORMATIONAL,
    "retire_asset": SyslogSeverity.NOTICE,
    "unretire_asset": SyslogSeverity.NOTICE,
    "assign_group": SyslogSeverity.INFORMATIONAL,

    # Baseline events
    "upload_changes": SyslogSeverity.INFORMATIONAL,
    "promote_initial_baseline": SyslogSeverity.NOTICE,
    "manual_config_edit": SyslogSeverity.NOTICE,
    "finalize_baselines": SyslogSeverity.NOTICE,

    # Change management events
    "change_approved": SyslogSeverity.INFORMATIONAL,
    "change_rejected": SyslogSeverity.WARNING,
    "change_investigation": SyslogSeverity.WARNING,
    "bulk_approved": SyslogSeverity.INFORMATIONAL,
    "bulk_rejected": SyslogSeverity.WARNING,
    "bulk_investigation": SyslogSeverity.WARNING,
    "revert_approval": SyslogSeverity.WARNING,
    "bulk_revert": SyslogSeverity.WARNING,

    # Scheduled events
    "scheduled_check": SyslogSeverity.INFORMATIONAL,
    "changes_detected": SyslogSeverity.WARNING,
    "folder_scan_new_asset": SyslogSeverity.INFORMATIONAL,
    "folder_scan_changes": SyslogSeverity.INFORMATIONAL,

    # Settings events
    "update_setting": SyslogSeverity.NOTICE,

    # Auth events
    "login_success": SyslogSeverity.INFORMATIONAL,
    "login_failed": SyslogSeverity.WARNING,
    "logout": SyslogSeverity.INFORMATIONAL,
}

# All available event types with descriptions
SYSLOG_EVENT_TYPES = [
    ("create_asset", "Asset Created", "A new asset was created in the system"),
    ("upload_changes", "Changes Uploaded", "Baseline changes were uploaded for an asset"),
    ("promote_initial_baseline", "Baseline Promoted", "Initial baseline was promoted to current"),
    ("assign_group", "Group Assigned", "Asset was assigned to a group"),
    ("manual_config_edit", "Manual Edit", "Configuration was manually edited"),
    ("delete_asset", "Asset Deleted", "An asset was deleted from the system"),
    ("rename_asset", "Asset Renamed", "An asset was renamed"),
    ("retire_asset", "Asset Retired", "An asset was retired"),
    ("unretire_asset", "Asset Unretired", "An asset was restored from retirement"),
    ("change_approved", "Change Approved", "A detected change was approved"),
    ("change_rejected", "Change Rejected", "A detected change was rejected"),
    ("change_investigation", "Investigation Started", "A change was marked for investigation"),
    ("bulk_approved", "Bulk Approval", "Multiple changes were approved at once"),
    ("bulk_rejected", "Bulk Rejection", "Multiple changes were rejected at once"),
    ("bulk_investigation", "Bulk Investigation", "Multiple changes marked for investigation"),
    ("finalize_baselines", "Baselines Finalized", "Approved changes were finalized into baselines"),
    ("revert_approval", "Approval Reverted", "An approved change was reverted"),
    ("bulk_revert", "Bulk Revert", "Multiple approvals were reverted"),
    ("scheduled_check", "Scheduled Check", "Automated compliance check was run"),
    ("changes_detected", "Changes Detected", "Scheduled check detected baseline changes"),
    ("folder_scan_new_asset", "Folder Scan - New Asset", "Watch folder scan created new asset"),
    ("folder_scan_changes", "Folder Scan - Changes", "Watch folder scan detected changes"),
    ("update_setting", "Setting Changed", "A system setting was modified"),
    ("login_success", "Login Success", "User logged in successfully"),
    ("login_failed", "Login Failed", "Failed login attempt"),
    ("logout", "Logout", "User logged out"),
]


class SyslogService:
    """
    RFC 5424 Syslog service with per-event configurability.

    Sends structured syslog messages to remote collectors via UDP, TCP, or TLS.
    """

    # IANA Private Enterprise Number for structured data
    # Using a placeholder - in production, register with IANA
    ENTERPRISE_ID = "32473"

    def __init__(self, db_session_factory: Callable):
        """Initialize syslog service with database session factory."""
        self.db_session_factory = db_session_factory
        self._config_cache: Optional[Dict[str, Any]] = None
        self._config_cache_time: Optional[datetime] = None
        self._cache_ttl_seconds = 60  # Cache config for 1 minute
        self._hostname = self._get_hostname()

    def _get_hostname(self) -> str:
        """Get the system hostname."""
        try:
            return socket.getfqdn()
        except Exception:
            return socket.gethostname()

    def _get_config(self) -> Dict[str, Any]:
        """Get syslog configuration from database with caching."""
        now = datetime.now(timezone.utc)

        # Return cached config if still valid
        if (self._config_cache is not None and
            self._config_cache_time is not None and
            (now - self._config_cache_time).total_seconds() < self._cache_ttl_seconds):
            return self._config_cache

        # Fetch from database
        config = {
            "syslog_enabled": False,
            "syslog_server": "",
            "syslog_port": 514,
            "syslog_protocol": "udp",
            "syslog_facility": 16,  # LOCAL0
            "syslog_tls_verify": True,
            "syslog_tls_ca_cert": "",
            "syslog_enabled_events": {},
        }

        try:
            from database import SystemSetting
            db = self.db_session_factory()
            try:
                settings = db.query(SystemSetting).filter(
                    SystemSetting.key.like("syslog_%")
                ).all()

                for setting in settings:
                    if setting.key == "syslog_enabled":
                        config["syslog_enabled"] = setting.value.lower() == "true" if setting.value else False
                    elif setting.key == "syslog_server":
                        config["syslog_server"] = setting.value or ""
                    elif setting.key == "syslog_port":
                        config["syslog_port"] = int(setting.value) if setting.value else 514
                    elif setting.key == "syslog_protocol":
                        config["syslog_protocol"] = setting.value or "udp"
                    elif setting.key == "syslog_facility":
                        config["syslog_facility"] = int(setting.value) if setting.value else 16
                    elif setting.key == "syslog_tls_verify":
                        config["syslog_tls_verify"] = setting.value.lower() == "true" if setting.value else True
                    elif setting.key == "syslog_tls_ca_cert":
                        config["syslog_tls_ca_cert"] = setting.value or ""
                    elif setting.key == "syslog_enabled_events":
                        try:
                            config["syslog_enabled_events"] = json.loads(setting.value) if setting.value else {}
                        except json.JSONDecodeError:
                            config["syslog_enabled_events"] = {}
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"Failed to load syslog config from database: {e}")

        self._config_cache = config
        self._config_cache_time = now
        return config

    def clear_cache(self):
        """Clear configuration cache."""
        self._config_cache = None
        self._config_cache_time = None

    def is_enabled(self) -> bool:
        """Check if syslog is globally enabled."""
        config = self._get_config()
        return config.get("syslog_enabled", False) and bool(config.get("syslog_server"))

    def is_event_enabled(self, event_type: str) -> bool:
        """Check if a specific event type is enabled for syslog."""
        if not self.is_enabled():
            return False
        config = self._get_config()
        enabled_events = config.get("syslog_enabled_events", {})
        return enabled_events.get(event_type, False)

    def _calculate_priority(self, facility: int, severity: int) -> int:
        """Calculate RFC 5424 priority value."""
        return facility * 8 + severity

    def _format_rfc5424_message(
        self,
        event_type: str,
        message: str,
        structured_data: Optional[Dict[str, Any]] = None,
        severity: Optional[SyslogSeverity] = None,
        facility: Optional[SyslogFacility] = None,
    ) -> bytes:
        """
        Format a message according to RFC 5424.

        Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID SD-PARAMS] MSG
        """
        config = self._get_config()

        # Use provided values or defaults
        if facility is None:
            facility = SyslogFacility(config.get("syslog_facility", 16))
        if severity is None:
            severity = EVENT_SEVERITY_MAP.get(event_type, SyslogSeverity.INFORMATIONAL)

        # Calculate priority
        pri = self._calculate_priority(facility, severity)

        # Version
        version = 1

        # Timestamp in RFC 5424 format (ISO 8601)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Hostname
        hostname = self._hostname

        # App name
        app_name = "fiducia"

        # Process ID
        procid = str(os.getpid())

        # Message ID (use event type)
        msgid = event_type.upper()

        # Structured data
        sd = "-"
        if structured_data:
            # Build SD-ELEMENT: [SD-ID SD-PARAM...]
            sd_params = []
            for key, value in structured_data.items():
                # Escape special characters in SD-PARAM values
                safe_value = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
                sd_params.append(f'{key}="{safe_value}"')

            if sd_params:
                sd = f"[fiducia@{self.ENTERPRISE_ID} {' '.join(sd_params)}]"

        # Build the message
        # Format: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA SP MSG
        syslog_msg = f"<{pri}>{version} {timestamp} {hostname} {app_name} {procid} {msgid} {sd} {message}"

        return syslog_msg.encode("utf-8")

    def _send_udp(self, message: bytes, server: str, port: int) -> bool:
        """Send message via UDP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(message, (server, port))
            sock.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send syslog via UDP to {server}:{port}: {e}")
            return False

    def _send_tcp(self, message: bytes, server: str, port: int) -> bool:
        """Send message via TCP with octet counting framing (RFC 6587)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))

            # RFC 6587 octet counting: MSG-LEN SP SYSLOG-MSG
            framed_message = f"{len(message)} ".encode("utf-8") + message
            sock.sendall(framed_message)
            sock.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send syslog via TCP to {server}:{port}: {e}")
            return False

    def _send_tls(self, message: bytes, server: str, port: int,
                  verify_cert: bool = True, ca_cert_path: Optional[str] = None) -> bool:
        """Send message via TLS encrypted connection."""
        try:
            # Create SSL context
            context = ssl.create_default_context()

            if not verify_cert:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            elif ca_cert_path and os.path.exists(ca_cert_path):
                context.load_verify_locations(ca_cert_path)

            # Create socket and wrap with TLS
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)

            with context.wrap_socket(sock, server_hostname=server) as ssock:
                ssock.connect((server, port))

                # RFC 6587 octet counting framing
                framed_message = f"{len(message)} ".encode("utf-8") + message
                ssock.sendall(framed_message)

            return True
        except Exception as e:
            logger.error(f"Failed to send syslog via TLS to {server}:{port}: {e}")
            return False

    def send_event(
        self,
        event_type: str,
        message: str,
        asset_id: Optional[int] = None,
        asset_name: Optional[str] = None,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Send an audit event to syslog if enabled.

        This is the main entry point called from audit logging code.
        """
        if not self.is_event_enabled(event_type):
            return False

        config = self._get_config()
        server = config.get("syslog_server", "")
        port = config.get("syslog_port", 514)
        protocol = config.get("syslog_protocol", "udp")

        if not server:
            return False

        # Build structured data
        sd = {"event": event_type}
        if asset_id:
            sd["asset_id"] = str(asset_id)
        if asset_name:
            sd["asset"] = asset_name
        if user_id:
            sd["user_id"] = str(user_id)
        if username:
            sd["user"] = username

        # Add selected details (limit to avoid huge messages)
        if details:
            for key in ["ticket_number", "change_count", "group", "old_name", "new_name"]:
                if key in details:
                    sd[key] = str(details[key])

        # Format the message
        syslog_message = self._format_rfc5424_message(
            event_type=event_type,
            message=message,
            structured_data=sd
        )

        # Send based on protocol
        if protocol == SyslogProtocol.UDP.value:
            return self._send_udp(syslog_message, server, port)
        elif protocol == SyslogProtocol.TCP.value:
            return self._send_tcp(syslog_message, server, port)
        elif protocol == SyslogProtocol.TLS.value:
            verify = config.get("syslog_tls_verify", True)
            ca_cert = config.get("syslog_tls_ca_cert", "")
            return self._send_tls(syslog_message, server, port, verify, ca_cert or None)
        else:
            logger.warning(f"Unknown syslog protocol: {protocol}")
            return False

    def test_connection(self) -> Dict[str, Any]:
        """Test syslog connection with current settings."""
        config = self._get_config()
        server = config.get("syslog_server", "")
        port = config.get("syslog_port", 514)
        protocol = config.get("syslog_protocol", "udp")

        if not server:
            return {
                "success": False,
                "error": "No syslog server configured"
            }

        # Build test message
        test_message = self._format_rfc5424_message(
            event_type="test_connection",
            message="Fiducia syslog test message",
            structured_data={"test": "true", "timestamp": datetime.now(timezone.utc).isoformat()}
        )

        try:
            if protocol == SyslogProtocol.UDP.value:
                success = self._send_udp(test_message, server, port)
            elif protocol == SyslogProtocol.TCP.value:
                success = self._send_tcp(test_message, server, port)
            elif protocol == SyslogProtocol.TLS.value:
                verify = config.get("syslog_tls_verify", True)
                ca_cert = config.get("syslog_tls_ca_cert", "")
                success = self._send_tls(test_message, server, port, verify, ca_cert or None)
            else:
                return {
                    "success": False,
                    "error": f"Unknown protocol: {protocol}"
                }

            if success:
                return {
                    "success": True,
                    "message": f"Test message sent via {protocol.upper()} to {server}:{port}"
                }
            else:
                return {
                    "success": False,
                    "error": f"Failed to send test message via {protocol.upper()}"
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# Global syslog service instance (initialized in main.py)
syslog_service: Optional[SyslogService] = None


def get_syslog_service() -> Optional[SyslogService]:
    """Get the global syslog service instance."""
    return syslog_service


def init_syslog_service(db_session_factory: Callable) -> SyslogService:
    """Initialize the global syslog service instance."""
    global syslog_service
    syslog_service = SyslogService(db_session_factory)
    return syslog_service
