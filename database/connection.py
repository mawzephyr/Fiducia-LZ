"""
Database connection and session management.

Supports multiple database backends:
- SQLite (default, file-based)
- PostgreSQL
- MySQL
- SQL Server
"""
import logging
from urllib.parse import urlparse

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from config import settings

logger = logging.getLogger(__name__)


def get_database_type() -> str:
    """Determine database type from URL."""
    url = settings.DATABASE_URL.lower()
    if url.startswith("sqlite"):
        return "sqlite"
    elif url.startswith("postgresql") or url.startswith("postgres"):
        return "postgresql"
    elif url.startswith("mysql"):
        return "mysql"
    elif url.startswith("mssql"):
        return "mssql"
    else:
        return "unknown"


def create_db_engine():
    """Create database engine with appropriate settings for the database type."""
    db_type = get_database_type()

    if db_type == "sqlite":
        # SQLite - simple file-based, no connection pooling
        return create_engine(
            settings.DATABASE_URL,
            connect_args={"check_same_thread": False},
            echo=settings.DEBUG
        )
    else:
        # Production databases - use connection pooling
        return create_engine(
            settings.DATABASE_URL,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.DATABASE_POOL_TIMEOUT,
            pool_pre_ping=True,  # Verify connections before use
            echo=settings.DEBUG
        )


engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency for FastAPI to get database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables."""
    from database.models import (
        Asset, BaselineSnapshot, Change, AuditLog, Report,
        ScheduledCheck, User, Group, SystemSetting
    )
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database initialized: {get_database_type()}")

    # Run migrations for new columns
    _run_migrations()


def _run_migrations():
    """Run database migrations for new columns."""
    db_type = get_database_type()

    migrations = [
        # v3.5.1: Add ticket_number to changes table
        ("changes", "ticket_number", "VARCHAR(100)"),
        # v3.5.1: Add ticket_number to baseline_snapshots table
        ("baseline_snapshots", "ticket_number", "VARCHAR(100)"),
        # v3.5.4: Add field_tickets_json for per-field ticket persistence
        ("baseline_snapshots", "field_tickets_json", "TEXT"),
        # v3.7.3: Add asset_name to audit_logs for persistence after asset deletion
        ("audit_logs", "asset_name", "VARCHAR(255)"),
        # v3.7.4: Security - account lockout fields
        ("users", "failed_login_attempts", "INTEGER DEFAULT 0"),
        ("users", "locked_until", "DATETIME"),
        ("users", "last_failed_login", "DATETIME"),
    ]

    with engine.connect() as conn:
        for table, column, col_type in migrations:
            try:
                # Check if column exists
                if db_type == "sqlite":
                    result = conn.execute(text(f"PRAGMA table_info({table})"))
                    columns = [row[1] for row in result.fetchall()]
                    if column not in columns:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                        conn.commit()
                        logger.info(f"Migration: Added {column} to {table}")
                elif db_type == "postgresql":
                    conn.execute(text(f"""
                        DO $$ BEGIN
                            ALTER TABLE {table} ADD COLUMN {column} {col_type};
                        EXCEPTION
                            WHEN duplicate_column THEN NULL;
                        END $$;
                    """))
                    conn.commit()
                    logger.info(f"Migration: Checked {column} on {table}")
                elif db_type == "mysql":
                    # MySQL: Check information_schema
                    result = conn.execute(text(f"""
                        SELECT COUNT(*) FROM information_schema.columns
                        WHERE table_name = '{table}' AND column_name = '{column}'
                    """))
                    if result.scalar() == 0:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"))
                        conn.commit()
                        logger.info(f"Migration: Added {column} to {table}")
                elif db_type == "mssql":
                    result = conn.execute(text(f"""
                        SELECT COUNT(*) FROM sys.columns
                        WHERE object_id = OBJECT_ID('{table}') AND name = '{column}'
                    """))
                    if result.scalar() == 0:
                        conn.execute(text(f"ALTER TABLE {table} ADD {column} {col_type}"))
                        conn.commit()
                        logger.info(f"Migration: Added {column} to {table}")
            except Exception as e:
                logger.warning(f"Migration check for {table}.{column}: {e}")


def get_database_info() -> dict:
    """Get information about the current database connection."""
    db_type = get_database_type()
    parsed = urlparse(settings.DATABASE_URL)

    # Mask password in connection string
    safe_url = settings.DATABASE_URL
    if parsed.password:
        safe_url = safe_url.replace(parsed.password, "****")

    info = {
        "type": db_type,
        "driver": engine.dialect.name,
        "connection_string": safe_url,
        "pool_size": settings.DATABASE_POOL_SIZE if db_type != "sqlite" else "N/A",
        "max_overflow": settings.DATABASE_MAX_OVERFLOW if db_type != "sqlite" else "N/A",
    }

    # Test connection and get version
    try:
        with engine.connect() as conn:
            if db_type == "sqlite":
                result = conn.execute(text("SELECT sqlite_version()"))
                info["version"] = f"SQLite {result.scalar()}"
            elif db_type == "postgresql":
                result = conn.execute(text("SELECT version()"))
                info["version"] = result.scalar().split(",")[0]
            elif db_type == "mysql":
                result = conn.execute(text("SELECT version()"))
                info["version"] = f"MySQL {result.scalar()}"
            elif db_type == "mssql":
                result = conn.execute(text("SELECT @@VERSION"))
                info["version"] = result.scalar().split("\n")[0]
            else:
                info["version"] = "Unknown"
            info["status"] = "connected"
    except Exception as e:
        info["status"] = "error"
        info["error"] = str(e)
        info["version"] = "N/A"

    return info
