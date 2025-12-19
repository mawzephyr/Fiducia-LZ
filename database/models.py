"""
CIP-010 Baseline Engine Database Models

This implements the time-series tracking schema for baseline compliance.
"""
from datetime import datetime, date
from enum import Enum as PyEnum
from typing import Optional
import json
import hashlib

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Date, Boolean, 
    ForeignKey, Enum, JSON, Index
)
from sqlalchemy.orm import relationship
from database.connection import Base


class AssetState(str, PyEnum):
    """Asset compliance states."""
    ACTIVE = "active"
    COMPLIANT = "compliant"
    INVESTIGATION = "investigation"
    FAILED = "failed"
    RETIRED = "retired"


class ChangeStatus(str, PyEnum):
    """Change review status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    INVESTIGATION = "investigation"
    FAILED = "failed"  # Timer expired without resolution


class ChangeType(str, PyEnum):
    """Types of configuration changes."""
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    ARRAY_MODIFIED = "array_modified"
    ARRAY_ITEM_ADDED = "array_item_added"
    ARRAY_ITEM_REMOVED = "array_item_removed"


class ReportType(str, PyEnum):
    """Types of generated reports."""
    APPROVAL = "approval"
    REJECTION = "rejection"
    INVESTIGATION = "investigation"
    FINALIZATION = "finalization"
    SCHEDULED_AGGREGATE = "scheduled_aggregate"
    SCHEDULED_PER_ASSET = "scheduled_per_asset"
    MANUAL_COMPARISON = "manual_comparison"


class CheckStatus(str, PyEnum):
    """Scheduled check status."""
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================
# GROUPS
# ============================================================

class Group(Base):
    """Asset management groups (Server Team, Desktop Team, etc.)"""
    __tablename__ = "groups"
    
    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    color = Column(String(20), default="#6b7280")
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    assets = relationship("Asset", back_populates="group")
    users = relationship("User", back_populates="group")


# ============================================================
# USERS
# ============================================================

class User(Base):
    """System users for authentication and audit trail."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(50), default="baseline_expert")  # admin, baseline_expert
    group_id = Column(String(50), ForeignKey("groups.id"), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(50), nullable=True)
    last_login = Column(DateTime, nullable=True)

    # Security: Account lockout after failed attempts
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_failed_login = Column(DateTime, nullable=True)

    # Relationships
    group = relationship("Group", back_populates="users")
    audit_logs = relationship("AuditLog", back_populates="user")


# ============================================================
# ASSETS
# ============================================================

class Asset(Base):
    """
    Core asset table - represents a tracked network device/system.
    This is the foundation for baseline tracking.
    """
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_name = Column(String(100), unique=True, nullable=False, index=True)
    group_id = Column(String(50), ForeignKey("groups.id"), nullable=True)
    
    # Current state tracking
    current_state = Column(Enum(AssetState), default=AssetState.ACTIVE)
    state_changed_at = Column(DateTime, default=datetime.utcnow)
    days_in_current_state = Column(Integer, default=0)
    
    # Compliance tracking
    last_baseline_check = Column(DateTime, nullable=True)
    last_approved_change = Column(DateTime, nullable=True)
    # NOTE: compliance_due_date removed in v4.0.0 - timers are now per-change
    
    # Metadata from config
    fqdn = Column(String(255), nullable=True)
    version = Column(String(50), nullable=True)

    # Retirement tracking
    retired_at = Column(DateTime, nullable=True)
    retired_by = Column(String(50), nullable=True)
    retirement_ticket = Column(String(100), nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    group = relationship("Group", back_populates="assets")
    snapshots = relationship("BaselineSnapshot", back_populates="asset", cascade="all, delete-orphan")
    changes = relationship("Change", back_populates="asset", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index("idx_asset_state", "current_state"),
        Index("idx_asset_group", "group_id"),
    )
    
    def update_days_in_state(self):
        """Calculate days in current state."""
        if self.state_changed_at:
            delta = datetime.utcnow() - self.state_changed_at
            self.days_in_current_state = delta.days


# ============================================================
# BASELINE SNAPSHOTS (Time-Series Data)
# ============================================================

class BaselineSnapshot(Base):
    """
    Time-series baseline captures.
    Each snapshot represents the complete configuration at a point in time.
    """
    __tablename__ = "baseline_snapshots"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    
    # Snapshot data
    captured_at = Column(DateTime, default=datetime.utcnow, index=True)  # When we received it
    capture_timestamp = Column(DateTime, nullable=True)  # When the baseline was actually captured (from file)
    config_json = Column(Text, nullable=False)  # Full JSON configuration
    config_hash = Column(String(64), nullable=False, index=True)  # SHA-256 for quick comparison
    
    # Source tracking
    source = Column(String(50), default="manual_upload")  # manual_upload, scheduled_check, api
    triggered_by = Column(String(50), nullable=True)  # username or "system"
    filename = Column(String(255), nullable=True)  # Original filename if uploaded
    
    # Status
    is_current_baseline = Column(Boolean, default=False)
    promoted_at = Column(DateTime, nullable=True)
    promoted_by = Column(String(50), nullable=True)

    # Change management
    ticket_number = Column(String(100), nullable=True)  # Change management ticket #
    field_tickets_json = Column(Text, nullable=True)  # Per-field ticket numbers JSON

    # Relationships
    asset = relationship("Asset", back_populates="snapshots")
    
    __table_args__ = (
        Index("idx_snapshot_asset_time", "asset_id", "captured_at"),
    )
    
    @staticmethod
    def compute_hash(config: dict) -> str:
        """Compute SHA-256 hash of configuration for quick comparison."""
        # Sort keys for consistent hashing
        json_str = json.dumps(config, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode()).hexdigest()


# ============================================================
# CHANGES (Detected Differences)
# ============================================================

class Change(Base):
    """
    Individual configuration changes detected between baselines.
    Tracks approval/rejection status and investigation time.
    """
    __tablename__ = "changes"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    
    # What changed
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    field_path = Column(String(500), nullable=False)  # e.g., "ports_services_string"
    change_type = Column(Enum(ChangeType), nullable=False)
    old_value = Column(Text, nullable=True)  # JSON string
    new_value = Column(Text, nullable=True)  # JSON string
    
    # For array changes
    items_added = Column(Text, nullable=True)  # JSON array of added items
    items_removed = Column(Text, nullable=True)  # JSON array of removed items
    
    # Review status
    status = Column(Enum(ChangeStatus), default=ChangeStatus.PENDING, index=True)
    status_changed_at = Column(DateTime, nullable=True)
    status_changed_by = Column(String(50), nullable=True)
    
    # Investigation tracking
    investigation_started_at = Column(DateTime, nullable=True)
    days_in_investigation = Column(Integer, default=0)
    resolution_notes = Column(Text, nullable=True)

    # Per-change compliance timer (v4.0.0) - auto-set on creation
    compliance_due_date = Column(Date, nullable=True)  # 30 days from detection
    resolved_at = Column(DateTime, nullable=True)  # When approved/rejected (preserved for audit)
    
    # Grouping (for bulk approval of identical changes across assets)
    change_signature = Column(String(64), nullable=True, index=True)

    # Change management
    ticket_number = Column(String(100), nullable=True)  # Change management ticket #

    # Reference to snapshots
    old_snapshot_id = Column(Integer, ForeignKey("baseline_snapshots.id"), nullable=True)
    new_snapshot_id = Column(Integer, ForeignKey("baseline_snapshots.id"), nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="changes")
    
    __table_args__ = (
        Index("idx_change_status", "status"),
        Index("idx_change_asset_status", "asset_id", "status"),
    )
    
    def update_investigation_days(self):
        """Calculate days in investigation state."""
        if self.status == ChangeStatus.INVESTIGATION and self.investigation_started_at:
            delta = datetime.utcnow() - self.investigation_started_at
            self.days_in_investigation = delta.days
    
    @staticmethod
    def compute_signature(field_path: str, change_type: str, old_value, new_value) -> str:
        """
        Compute signature for grouping identical changes across assets.
        This enables the "grouped changes" feature from your HTML version.
        """
        sig_data = f"{field_path}|{change_type}|{json.dumps(old_value, sort_keys=True)}|{json.dumps(new_value, sort_keys=True)}"
        return hashlib.sha256(sig_data.encode()).hexdigest()[:16]


# ============================================================
# AUDIT LOG
# ============================================================

class AuditLog(Base):
    """
    Complete audit trail for compliance reporting.
    Every action is logged with timestamp and user.
    """
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # What happened
    action = Column(String(50), nullable=False)  # approve, reject, investigate, finalize, scheduled_check, etc.
    action_detail = Column(String(255), nullable=True)
    
    # What was affected (SET NULL on delete to preserve audit history)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    change_id = Column(Integer, ForeignKey("changes.id", ondelete="SET NULL"), nullable=True)
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="SET NULL"), nullable=True)

    # Preserve asset name for audit trail (populated when asset is deleted)
    asset_name = Column(String(255), nullable=True)
    
    # Additional context
    details_json = Column(Text, nullable=True)  # JSON for any extra data
    ip_address = Column(String(45), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")
    
    __table_args__ = (
        Index("idx_audit_action", "action"),
        Index("idx_audit_asset", "asset_id"),
    )


# ============================================================
# REPORTS
# ============================================================

class Report(Base):
    """
    Generated reports for compliance documentation.
    These can be attached to tickets or exported.
    """
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_type = Column(Enum(ReportType), nullable=False)
    
    # Metadata
    generated_at = Column(DateTime, default=datetime.utcnow, index=True)
    generated_by = Column(String(50), nullable=True)  # username or "system"
    title = Column(String(255), nullable=False)
    
    # Content
    report_content = Column(Text, nullable=False)  # The actual report text
    
    # Related entities
    related_assets = Column(Text, nullable=True)  # JSON array of asset_ids
    related_changes = Column(Text, nullable=True)  # JSON array of change_ids
    
    # For scheduled reports
    scheduled_check_id = Column(Integer, ForeignKey("scheduled_checks.id"), nullable=True)


# ============================================================
# SCHEDULED CHECKS
# ============================================================

class ScheduledCheck(Base):
    """
    Tracks automated baseline verification runs.
    Supports your 15-day interval compliance checking.
    """
    __tablename__ = "scheduled_checks"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Schedule info
    scheduled_date = Column(Date, nullable=False, index=True)
    executed_at = Column(DateTime, nullable=True)

    # Trigger type: 'scheduled' for auto checks on 1st/15th, 'manual' for user-initiated
    trigger_type = Column(String(20), default="scheduled")  # 'scheduled' or 'manual'
    triggered_by = Column(String(50), nullable=True)  # username if manual

    # Results
    status = Column(Enum(CheckStatus), default=CheckStatus.PENDING)
    assets_checked = Column(Integer, default=0)
    changes_detected = Column(Integer, default=0)
    assets_unchanged = Column(Integer, default=0)
    assets_in_investigation = Column(Integer, default=0)
    assets_failed = Column(Integer, default=0)

    # Detailed investigation info - JSON array of investigated assets with reasons
    # Format: [{"asset_id": 1, "asset_name": "srv01", "reason": "new_changes", "changes": ["os", "firmware"]}]
    investigated_assets_json = Column(Text, nullable=True)

    # Reports generated
    aggregate_report_id = Column(Integer, ForeignKey("reports.id"), nullable=True)

    # Error tracking
    error_message = Column(Text, nullable=True)

    # Relationships
    reports = relationship("Report", foreign_keys=[aggregate_report_id])


# ============================================================
# SYSTEM SETTINGS
# ============================================================

class SystemSetting(Base):
    """
    Key-value store for system settings.
    Used for admin-configurable options like watch folder path.
    """
    __tablename__ = "system_settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(50), nullable=True)


# ============================================================
# USER SESSIONS
# ============================================================

class UserSession(Base):
    """
    Tracks active user sessions for single-session enforcement.
    When a user logs in, any existing sessions are invalidated.
    """
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_token = Column(String(64), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    is_active = Column(Boolean, default=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    # Relationships
    user = relationship("User", backref="sessions")

    __table_args__ = (
        Index("idx_session_user_active", "user_id", "is_active"),
    )
