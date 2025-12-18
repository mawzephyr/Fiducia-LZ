"""
Authentication routes for CIP-010 Baseline Engine.

Supports both LDAP and local authentication with offline caching.
Includes rate limiting and account lockout for security.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict
import threading
import bcrypt as bcrypt_lib

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from config import settings
from database import get_db, User, SessionLocal, AuditLog, UserSession
from api.schemas import Token, UserCreate, UserResponse, UserLogin
import secrets

logger = logging.getLogger(__name__)
router = APIRouter()

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
MAX_LOGIN_ATTEMPTS = 5           # Lock account after this many failed attempts
LOCKOUT_DURATION_MINUTES = 15    # How long to lock the account
RATE_LIMIT_WINDOW_SECONDS = 60   # Rate limit window
RATE_LIMIT_MAX_ATTEMPTS = 10     # Max login attempts per IP in the window

# In-memory rate limiting (per IP address)
_rate_limit_cache = defaultdict(list)
_rate_limit_lock = threading.Lock()


def _check_rate_limit(ip_address: str) -> bool:
    """Check if IP is rate limited. Returns True if allowed, False if limited."""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)

    with _rate_limit_lock:
        # Clean old entries
        _rate_limit_cache[ip_address] = [
            t for t in _rate_limit_cache[ip_address] if t > cutoff
        ]

        # Check limit
        if len(_rate_limit_cache[ip_address]) >= RATE_LIMIT_MAX_ATTEMPTS:
            return False

        # Record this attempt
        _rate_limit_cache[ip_address].append(now)
        return True


def _get_client_ip(request: Request) -> str:
    """Get client IP from request, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# LDAP service instance (lazy loaded)
_ldap_service = None


def get_ldap_service():
    """Get or create LDAP service instance."""
    global _ldap_service
    if _ldap_service is None:
        from services.ldap_auth import LDAPAuthService
        _ldap_service = LDAPAuthService(lambda: SessionLocal())
    return _ldap_service

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash."""
    return bcrypt_lib.checkpw(
        plain_password.encode('utf-8'), 
        hashed_password.encode('utf-8')
    )


def get_password_hash(password: str) -> str:
    """Hash a password."""
    salt = bcrypt_lib.gensalt()
    return bcrypt_lib.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def _create_user_session(
    user: User,
    db: Session,
    ip_address: str = None,
    user_agent: str = None
) -> str:
    """
    Create a new session for a user, invalidating any existing sessions.
    Returns the session token.
    """
    # Invalidate all existing active sessions for this user
    db.query(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.is_active == True
    ).update({"is_active": False})

    # Create new session token
    session_token = secrets.token_hex(32)
    expires_at = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    session = UserSession(
        user_id=user.id,
        session_token=session_token,
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent and len(user_agent) > 255 else user_agent
    )
    db.add(session)
    db.commit()

    logger.info(f"Created new session for user {user.username}, invalidated previous sessions")
    return session_token


def _validate_session(session_token: str, db: Session) -> Optional[UserSession]:
    """
    Validate a session token. Returns the session if valid, None otherwise.
    """
    session = db.query(UserSession).filter(
        UserSession.session_token == session_token,
        UserSession.is_active == True
    ).first()

    if not session:
        return None

    # Check if session has expired
    if session.expires_at < datetime.utcnow():
        session.is_active = False
        db.commit()
        return None

    return session


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    session_expired_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired or logged in elsewhere",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        session_token: str = payload.get("session")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Validate session if session token is present in JWT
    if session_token:
        session = _validate_session(session_token, db)
        if not session:
            raise session_expired_exception

    return user


async def get_current_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def _check_account_lockout(user: User) -> Optional[str]:
    """Check if account is locked. Returns error message if locked, None if OK."""
    if user.locked_until and user.locked_until > datetime.utcnow():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60
        return f"Account locked. Try again in {remaining + 1} minutes."
    return None


def _record_failed_attempt(user: User, db: Session):
    """Record a failed login attempt, potentially locking the account."""
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    user.last_failed_login = datetime.utcnow()

    if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        logger.warning(f"Account {user.username} locked after {user.failed_login_attempts} failed attempts")

    db.commit()


def _reset_failed_attempts(user: User, db: Session):
    """Reset failed attempt counter on successful login."""
    if user.failed_login_attempts and user.failed_login_attempts > 0:
        user.failed_login_attempts = 0
        user.locked_until = None
        db.commit()


def authenticate_user(username: str, password: str, db: Session) -> tuple[Optional[dict], Optional[str]]:
    """
    Authenticate user with LDAP first, then fall back to local.

    Returns:
        Tuple of (user_info dict or None, error message or None)
    """
    # Get local user first to check lockout status
    local_user = db.query(User).filter(User.username == username).first()

    # Check account lockout (for local users)
    if local_user:
        lockout_msg = _check_account_lockout(local_user)
        if lockout_msg:
            return None, lockout_msg

    # Try LDAP authentication first
    ldap_service = get_ldap_service()
    if ldap_service.is_ldap_enabled():
        ldap_result = ldap_service.authenticate(username, password)
        if ldap_result:
            logger.info(f"LDAP auth successful for {username} (method={ldap_result['auth_method']})")
            # Reset failed attempts if user also exists locally
            if local_user:
                _reset_failed_attempts(local_user, db)
            return ldap_result, None

    # Fall back to local authentication
    if local_user and verify_password(password, local_user.password_hash):
        if not local_user.is_active:
            return None, "Account is disabled"
        _reset_failed_attempts(local_user, db)
        local_user.last_login = datetime.utcnow()
        db.commit()
        return {
            'username': local_user.username,
            'full_name': local_user.full_name,
            'role': local_user.role,
            'group_id': local_user.group_id,
            'auth_method': 'local'
        }, None

    # Authentication failed - record attempt if user exists
    if local_user:
        _record_failed_attempt(local_user, db)
        remaining = MAX_LOGIN_ATTEMPTS - (local_user.failed_login_attempts or 0)
        if remaining > 0:
            return None, f"Incorrect password. {remaining} attempts remaining."
        else:
            return None, f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes."

    return None, "Incorrect username or password"


@router.post("/login", response_model=Token)
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT token."""
    # Check rate limit
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )

    auth_result, error_msg = authenticate_user(form_data.username, form_data.password, db)

    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg or "Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user from database to create session
    user = db.query(User).filter(User.username == auth_result['username']).first()
    user_agent = request.headers.get("User-Agent")

    # Create session (invalidates any existing sessions for this user)
    session_token = _create_user_session(user, db, ip_address=client_ip, user_agent=user_agent)

    access_token = create_access_token(
        data={
            "sub": auth_result['username'],
            "role": auth_result['role'],
            "group": auth_result['group_id'],
            "session": session_token
        }
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/login/json", response_model=Token)
async def login_json(
    request: Request,
    credentials: UserLogin,
    db: Session = Depends(get_db)
):
    """Authenticate user with JSON body and return JWT token."""
    # Check rate limit
    client_ip = _get_client_ip(request)
    if not _check_rate_limit(client_ip):
        logger.warning(f"Rate limit exceeded for IP {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )

    auth_result, error_msg = authenticate_user(credentials.username, credentials.password, db)

    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=error_msg or "Incorrect username or password"
        )

    # Get user from database to create session
    user = db.query(User).filter(User.username == auth_result['username']).first()
    user_agent = request.headers.get("User-Agent")

    # Create session (invalidates any existing sessions for this user)
    session_token = _create_user_session(user, db, ip_address=client_ip, user_agent=user_agent)

    access_token = create_access_token(
        data={
            "sub": auth_result['username'],
            "role": auth_result['role'],
            "group": auth_result['group_id'],
            "session": session_token
        }
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return current_user


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """List all users (admin only)."""
    return db.query(User).all()


@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Create new user (admin only)."""
    # Check if username exists
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    user = User(
        username=user_data.username,
        password_hash=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
        group_id=user_data.group_id,
        created_by=current_user.username
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user


@router.delete("/users/{username}")
async def delete_user(
    username: str,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Delete user (admin only)."""
    if username == current_user.username:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    db.delete(user)
    db.commit()
    
    return {"message": f"User {username} deleted"}


@router.put("/users/{username}/password")
async def reset_password(
    username: str,
    new_password: str,
    current_user: User = Depends(get_current_admin),
    db: Session = Depends(get_db)
):
    """Reset user password (admin only)."""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user.password_hash = get_password_hash(new_password)
    
    # Audit log for password reset (admin action)
    is_self_reset = current_user.id == user.id
    audit = AuditLog(
        user_id=current_user.id,
        action="password_reset",
        action_detail=f"Password reset for user '{username}'" + (" (self)" if is_self_reset else f" by admin '{current_user.username}'"),
        details_json=json.dumps({
            "target_user_id": user.id,
            "target_username": username,
            "admin_user_id": current_user.id,
            "admin_username": current_user.username,
            "is_self_reset": is_self_reset
        })
    )
    db.add(audit)
    db.commit()
    
    return {"message": f"Password reset for {username}"}
