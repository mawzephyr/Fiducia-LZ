# Fiducia v4.0.7
"""
Database package for CIP-010 Baseline Engine.

Supports multiple SQL backends:
- SQLite (default)
- PostgreSQL
- MySQL
- SQL Server
"""
from database.connection import (
    Base, engine, SessionLocal, get_db, init_db,
    get_database_type, get_database_info
)
from database.models import (
    Asset, AssetState,
    BaselineSnapshot,
    Change, ChangeStatus, ChangeType,
    AuditLog,
    Report, ReportType,
    ScheduledCheck, CheckStatus,
    User, Group,
    SystemSetting,
    UserSession
)

__all__ = [
    "Base", "engine", "SessionLocal", "get_db", "init_db",
    "get_database_type", "get_database_info",
    "Asset", "AssetState",
    "BaselineSnapshot",
    "Change", "ChangeStatus", "ChangeType",
    "AuditLog",
    "Report", "ReportType",
    "ScheduledCheck", "CheckStatus",
    "User", "Group",
    "SystemSetting",
    "UserSession"
]
