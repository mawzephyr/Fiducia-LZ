"""
Fiducia - Infrastructure Baseline Management
"""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    # Application Info
    APP_NAME: str = "Fiducia"
    APP_VERSION: str = "4.0.4"
    DEBUG: bool = False
    
    # Database
    # Supported formats:
    #   SQLite:     sqlite:///./data/cip010.db (relative) or sqlite:////absolute/path/data/cip010.db
    #   PostgreSQL: postgresql://user:password@localhost:5432/cip010
    #   MySQL:      mysql+pymysql://user:password@localhost:3306/cip010
    #   SQL Server: mssql+pyodbc://user:password@localhost/cip010?driver=ODBC+Driver+17+for+SQL+Server
    DATABASE_URL: str = "sqlite:///./data/cip010.db"

    # Connection pool settings (ignored for SQLite)
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30
    
    # File Watching
    WATCH_DIRECTORY: Optional[str] = None  # Set to enable auto-ingestion
    WATCH_POLL_INTERVAL: int = 5  # seconds
    
    # Scheduling
    SCHEDULED_CHECK_DAYS: list[int] = [1, 15]  # Days of month to run auto-checks

    # Compliance Settings (defaults - can be overridden via UI)
    COMPLIANCE_WINDOW_DAYS: int = 30  # Days to update baseline after change detection (per-change timer)
    GREEN_THRESHOLD_DAYS: int = 10    # Days remaining to show green "On Track"
    YELLOW_THRESHOLD_DAYS: int = 5    # Days remaining to show yellow "Warning"
    CRITICAL_THRESHOLD_DAYS: int = 1  # Days remaining to show orange "Critical"

    # Compliance Behavior
    REQUIRE_RESOLUTION_NOTES: bool = False  # Require notes when approving/rejecting
    AUTO_PNCI_ON_FAILURE: bool = False      # Auto-generate PNCI when asset goes FAILED
    ALLOW_DEADLINE_EXTENSION: bool = False  # Allow extending compliance deadline
    MAX_EXTENSION_DAYS: int = 15            # Max days that can be added to deadline
    SHOW_COMPLIANCE_PERCENTAGE: bool = True # Show overall compliance % on dashboard
    HISTORICAL_RETENTION_DAYS: int = 365    # Days of historical compliance data to keep
    
    # Email Notifications (defaults - can be overridden via UI)
    SMTP_ENABLED: bool = False
    SMTP_PORT: int = 587
    SMTP_USE_TLS: bool = True
    SMTP_TIMEOUT: int = 30

    # Authentication
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours

    # CORS - comma-separated list of allowed origins, or "*" for all (not recommended)
    # Example: "https://fiducia.example.com,https://admin.example.com"
    CORS_ORIGINS: str = "*"

    # Security Settings
    # Allowed hosts for Host header validation (comma-separated, or "*" to disable)
    # Example: "fiducia.example.com,localhost"
    ALLOWED_HOSTS: str = "*"

    # Maximum request body size in bytes (10MB default)
    MAX_REQUEST_SIZE: int = 10 * 1024 * 1024

    # Session security
    SESSION_COOKIE_SECURE: bool = False  # Set True when behind HTTPS
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"  # "Strict", "Lax", or "None"

    # Paths
    BASE_DIR: Path = Path(__file__).parent
    REPORTS_DIR: Path = BASE_DIR / "reports"
    UPLOADS_DIR: Path = BASE_DIR / "uploads"
    
    # Groups (matching your HTML version)
    ASSET_GROUPS: list[dict] = [
        {"id": "server", "name": "Server Team", "color": "#3b82f6"},
        {"id": "desktop", "name": "Desktop Team", "color": "#22c55e"},
        {"id": "network", "name": "Network Team", "color": "#a855f7"},
        {"id": "telecom", "name": "Telecom Team", "color": "#f97316"},
    ]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()

# Security warning for default SECRET_KEY
if settings.SECRET_KEY == "your-secret-key-change-in-production":
    import warnings
    warnings.warn(
        "\n" + "=" * 70 + "\n"
        "⚠️  SECURITY WARNING: Using default SECRET_KEY!\n"
        "Set a secure SECRET_KEY environment variable in production:\n"
        '  export SECRET_KEY="$(openssl rand -hex 32)"\n'
        "=" * 70,
        UserWarning
    )

# Ensure directories exist
settings.REPORTS_DIR.mkdir(exist_ok=True)
settings.UPLOADS_DIR.mkdir(exist_ok=True)
