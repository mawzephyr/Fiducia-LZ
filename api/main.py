"""
CIP-010 Baseline Engine - FastAPI Application

Main entry point for the API server.
"""
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config import settings


# =============================================================================
# SECURITY HEADERS MIDDLEWARE
# =============================================================================
class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request body size to prevent DoS attacks."""

    async def dispatch(self, request: Request, call_next):
        # Check Content-Length header if present
        content_length = request.headers.get("content-length")
        if content_length:
            if int(content_length) > settings.MAX_REQUEST_SIZE:
                return Response(
                    content='{"detail": "Request body too large"}',
                    status_code=413,
                    media_type="application/json"
                )
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS Protection (legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy (restrict browser features)
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy - adjust as needed for your deployment
        # This is a restrictive policy; you may need to loosen for CDN resources
        if not settings.DEBUG:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )

        # Strict Transport Security (HSTS) - only when behind HTTPS proxy
        # Uncomment when deployed behind HTTPS reverse proxy:
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


from database import init_db, SessionLocal
from services.watcher import WatcherService
from services.scheduler import SchedulerService

# Configure logging
logging.basicConfig(
    level=logging.INFO if settings.DEBUG else logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global service instances
watcher_service: Optional[WatcherService] = None
scheduler_service: Optional[SchedulerService] = None
syslog_service = None  # Initialized in lifespan


def get_db_session():
    """Get a database session."""
    return SessionLocal()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown."""
    global watcher_service, scheduler_service, syslog_service

    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Initialize database
    init_db()
    logger.info("Database initialized")
    
    # Initialize default data (groups, admin user)
    initialize_default_data()
    
    # Start watcher service if configured
    if settings.WATCH_DIRECTORY:
        watcher_service = WatcherService(get_db_session)
        try:
            watcher_service.start(settings.WATCH_DIRECTORY)
        except FileNotFoundError:
            logger.warning(f"Watch directory not found: {settings.WATCH_DIRECTORY}")
    
    # Start scheduler service
    scheduler_service = SchedulerService(get_db_session)
    scheduler_service.start()

    # Initialize syslog service
    from services.syslog import init_syslog_service
    syslog_service = init_syslog_service(get_db_session)
    logger.info("Syslog service initialized")

    yield
    
    # Shutdown
    logger.info("Shutting down...")
    
    if watcher_service:
        watcher_service.stop()
    
    if scheduler_service:
        scheduler_service.stop()
    
    logger.info("Shutdown complete")


def initialize_default_data():
    """Initialize default groups and admin user."""
    from database import Group, User
    import bcrypt as bcrypt_lib
    
    def hash_password(password: str) -> str:
        salt = bcrypt_lib.gensalt()
        return bcrypt_lib.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    db = SessionLocal()
    try:
        # Create default groups if they don't exist
        for group_data in settings.ASSET_GROUPS:
            existing = db.query(Group).filter(Group.id == group_data["id"]).first()
            if not existing:
                group = Group(
                    id=group_data["id"],
                    name=group_data["name"],
                    color=group_data["color"]
                )
                db.add(group)
                logger.info(f"Created group: {group_data['name']}")
        
        # Create admin user if no users exist
        user_count = db.query(User).count()
        if user_count == 0:
            admin = User(
                username="admin",
                password_hash=hash_password("admin123"),
                full_name="Administrator",
                role="admin",
                group_id=None
            )
            db.add(admin)
            logger.info("Created default admin user (admin/admin123)")
            
            # Create default baseline expert users for each group
            for group_data in settings.ASSET_GROUPS:
                user = User(
                    username=group_data["id"],
                    password_hash=hash_password(f"{group_data['id']}123"),
                    full_name=f"{group_data['name']} Baseline Expert",
                    role="baseline_expert",
                    group_id=group_data["id"]
                )
                db.add(user)
                logger.info(f"Created user: {group_data['id']}")
        
        db.commit()
    finally:
        db.close()


# Create FastAPI app
# Disable API docs in production for security
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="CIP-010 Configuration Baseline Management System",
    lifespan=lifespan,
    # Disable Swagger/ReDoc in production
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# =============================================================================
# SECURITY MIDDLEWARE (order matters - last added = first executed)
# =============================================================================

# 1. Request Size Limit - prevent DoS via large payloads
app.add_middleware(RequestSizeLimitMiddleware)

# 2. Security Headers - adds X-Frame-Options, CSP, etc.
app.add_middleware(SecurityHeadersMiddleware)

# 3. Trusted Host Middleware - prevent host header injection
# Configure ALLOWED_HOSTS in production (comma-separated list)
allowed_hosts = getattr(settings, 'ALLOWED_HOSTS', '*')
if allowed_hosts != '*':
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts.split(",")
    )

# 4. CORS middleware - configurable via CORS_ORIGINS env var
# WARNING: CORS_ORIGINS="*" is insecure for production!
cors_origins = settings.CORS_ORIGINS.split(",") if settings.CORS_ORIGINS != "*" else ["*"]
if settings.CORS_ORIGINS == "*" and not settings.DEBUG:
    logger.warning("⚠️  SECURITY WARNING: CORS_ORIGINS='*' is insecure for production!")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],  # Explicit methods instead of "*"
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],  # Explicit headers
)

# Import and include routers
from api.routes import assets, changes, auth, comparison, reports, system

app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])
app.include_router(changes.router, prefix="/api/changes", tags=["Changes"])
app.include_router(comparison.router, prefix="/api/compare", tags=["Comparison"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(system.router, prefix="/api/system", tags=["System"])


@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - return simple status page."""
    docs_link = '<p>See <a href="/docs">/docs</a> for full API documentation.</p>' if settings.DEBUG else ''
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{settings.APP_NAME}</title>
        <style>
            body {{ font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
            h1 {{ color: #003A70; }}
            .version {{ color: #666; }}
            .endpoints {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin-top: 20px; }}
            code {{ background: #e0e0e0; padding: 2px 6px; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <h1>🔒 {settings.APP_NAME}</h1>
        <p class="version">Version {settings.APP_VERSION}</p>
        <p>CIP-010 Configuration Baseline Management System</p>
        <p><a href="/app">→ Go to Application</a></p>

        <div class="endpoints">
            <h3>API Status</h3>
            <p>API is running. Authenticated requests required for all endpoints.</p>
            {docs_link}
        </div>
    </body>
    </html>
    """


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# Make services accessible to routes
def get_watcher_service() -> Optional[WatcherService]:
    return watcher_service


def get_scheduler_service() -> Optional[SchedulerService]:
    return scheduler_service


def get_syslog_service():
    """Get the global syslog service instance."""
    return syslog_service
