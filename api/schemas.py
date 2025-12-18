"""
Pydantic schemas for CIP-010 Baseline Engine API.
"""
from datetime import datetime, date
from typing import Optional, Any
from pydantic import BaseModel, Field


# ============================================================
# AUTH SCHEMAS
# ============================================================

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


class UserBase(BaseModel):
    username: str
    full_name: str
    role: str = "baseline_expert"
    group_id: Optional[str] = None


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


# ============================================================
# GROUP SCHEMAS
# ============================================================

class GroupBase(BaseModel):
    id: str
    name: str
    color: str = "#6b7280"


class GroupResponse(GroupBase):
    created_at: datetime
    asset_count: int = 0
    
    class Config:
        from_attributes = True


# ============================================================
# ASSET SCHEMAS
# ============================================================

class AssetBase(BaseModel):
    asset_name: str
    group_id: Optional[str] = None
    fqdn: Optional[str] = None
    version: Optional[str] = None


class AssetCreate(AssetBase):
    config: dict


class AssetResponse(AssetBase):
    id: int
    current_state: str
    days_in_current_state: int
    last_baseline_check: Optional[datetime] = None
    last_approved_change: Optional[datetime] = None
    baseline_promoted_at: Optional[datetime] = None
    # NOTE: compliance_due_date removed in v4.0.0 - timers are now per-change
    retired_at: Optional[datetime] = None
    retired_by: Optional[str] = None
    retirement_ticket: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetDetail(AssetResponse):
    """Extended asset details including current config."""
    current_config: Optional[dict] = None
    pending_change_count: int = 0


class AssetGroupAssignment(BaseModel):
    group_id: str
    ticket_number: Optional[str] = None  # Change management ticket # for initial baseline


# ============================================================
# BASELINE SNAPSHOT SCHEMAS
# ============================================================

class SnapshotBase(BaseModel):
    source: str = "manual_upload"
    filename: Optional[str] = None


class SnapshotCreate(SnapshotBase):
    config: dict


class SnapshotResponse(SnapshotBase):
    id: int
    asset_id: int
    captured_at: datetime
    config_hash: str
    is_current_baseline: bool
    promoted_at: Optional[datetime] = None
    promoted_by: Optional[str] = None
    
    class Config:
        from_attributes = True


class SnapshotWithConfig(SnapshotResponse):
    config_json: str


# ============================================================
# CHANGE SCHEMAS
# ============================================================

class ChangeBase(BaseModel):
    field_path: str
    change_type: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    items_added: Optional[Any] = None
    items_removed: Optional[Any] = None


class ChangeResponse(ChangeBase):
    id: int
    asset_id: int
    detected_at: datetime
    status: str
    status_changed_at: Optional[datetime] = None
    status_changed_by: Optional[str] = None
    days_in_investigation: int = 0
    change_signature: Optional[str] = None
    resolution_notes: Optional[str] = None
    ticket_number: Optional[str] = None  # Change management ticket #
    compliance_due_date: Optional[date] = None  # Per-change timer (v4.0.0)
    resolved_at: Optional[datetime] = None  # When approved/rejected

    class Config:
        from_attributes = True


class ChangeWithAsset(ChangeResponse):
    """Change with asset info for bulk review."""
    asset_name: str
    asset_group_id: Optional[str] = None


class ChangeReview(BaseModel):
    """Request to approve/reject a change."""
    status: str = Field(..., pattern="^(approved|rejected|investigation)$")
    resolution_notes: Optional[str] = None
    ticket_number: Optional[str] = None  # Change management ticket #


class BulkChangeReview(BaseModel):
    """Request to approve/reject multiple changes by signature."""
    signature: str
    status: str = Field(..., pattern="^(approved|rejected|investigation)$")
    resolution_notes: Optional[str] = None
    ticket_number: Optional[str] = None  # Change management ticket #


# ============================================================
# COMPARISON SCHEMAS
# ============================================================

class ComparisonRequest(BaseModel):
    """Request to compare two configurations."""
    old_config: dict
    new_config: dict


class ConfigChangeSchema(BaseModel):
    path: str
    change_type: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    items_added: Optional[Any] = None
    items_removed: Optional[Any] = None
    added_count: Optional[int] = None
    removed_count: Optional[int] = None
    signature: str


class ComparisonResponse(BaseModel):
    is_identical: bool
    change_count: int
    old_hash: str
    new_hash: str
    changes: list[ConfigChangeSchema]


# ============================================================
# FILE UPLOAD SCHEMAS
# ============================================================

class FileUploadResult(BaseModel):
    """Result of uploading a baseline file."""
    filename: str
    asset_name: str
    is_new_asset: bool
    changes_detected: int = 0
    message: str


class BulkUploadResult(BaseModel):
    """Result of uploading multiple files."""
    files_processed: int
    new_assets: int
    updated_assets: int
    errors: list[str] = []
    results: list[FileUploadResult]


# ============================================================
# REPORT SCHEMAS
# ============================================================

class ReportBase(BaseModel):
    report_type: str
    title: str


class ReportResponse(ReportBase):
    id: int
    generated_at: datetime
    generated_by: Optional[str] = None
    report_content: str
    
    class Config:
        from_attributes = True


class ReportGenerate(BaseModel):
    """Request to generate a report."""
    report_type: str
    asset_ids: Optional[list[int]] = None
    change_ids: Optional[list[int]] = None


# ============================================================
# SCHEDULED CHECK SCHEMAS  
# ============================================================

class ScheduledCheckResponse(BaseModel):
    id: int
    scheduled_date: date
    executed_at: Optional[datetime] = None
    status: str
    assets_checked: int
    changes_detected: int
    assets_unchanged: int
    assets_in_investigation: int
    
    class Config:
        from_attributes = True


# ============================================================
# DASHBOARD / STATS SCHEMAS
# ============================================================

class DashboardStats(BaseModel):
    total_assets: int
    assets_by_group: dict[str, int]
    assets_by_state: dict[str, int]
    pending_changes: int
    pending_by_group: dict[str, int]
    new_assets_queue: int
    changes_approaching_deadline: int  # Per-change timers (v4.0.0)
    changes_past_deadline: int  # Per-change timers (v4.0.0)
    approved_changes: int = 0  # Changes approved but not yet finalized


class WatcherStats(BaseModel):
    is_running: bool
    files_processed: int
    new_assets: int
    updated_assets: int
    errors: int
    last_file: Optional[str] = None
    started_at: Optional[str] = None


class SchedulerStatus(BaseModel):
    is_running: bool
    scheduled_jobs: list[dict]
