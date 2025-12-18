"""
LDAP Authentication Service for CIP-010 Baseline Engine.

Provides LDAP authentication with offline caching support.
"""
import logging
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple
import bcrypt

from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, Tls
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError

logger = logging.getLogger(__name__)


class LDAPAuthService:
    """
    LDAP Authentication with offline caching.

    Features:
    - Authenticate users against LDAP/Active Directory
    - Query group membership for role mapping
    - Cache credentials for offline authentication
    - Configurable group-to-role mapping
    """

    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self._config_cache = None
        self._config_cache_time = None

    def _get_ldap_config(self) -> Dict:
        """Get LDAP configuration from database settings."""
        from database import SystemSetting

        # Cache config for 60 seconds to reduce DB queries
        if self._config_cache and self._config_cache_time:
            if datetime.utcnow() - self._config_cache_time < timedelta(seconds=60):
                return self._config_cache

        db = self.db_session_factory()
        try:
            settings = {}
            for key in ['ldap_enabled', 'ldap_server', 'ldap_port', 'ldap_use_ssl',
                        'ldap_bind_dn', 'ldap_bind_password', 'ldap_user_base_dn',
                        'ldap_user_filter', 'ldap_group_base_dn', 'ldap_group_filter',
                        'ldap_group_mapping', 'ldap_admin_groups', 'ldap_cache_hours']:
                setting = db.query(SystemSetting).filter(SystemSetting.key == key).first()
                settings[key] = setting.value if setting else None

            self._config_cache = settings
            self._config_cache_time = datetime.utcnow()
            return settings
        finally:
            db.close()

    def is_ldap_enabled(self) -> bool:
        """Check if LDAP authentication is enabled."""
        config = self._get_ldap_config()
        ldap_enabled = config.get('ldap_enabled') or ''
        return ldap_enabled.lower() == 'true'

    def _get_ldap_connection(self, user_dn: str = None, password: str = None) -> Optional[Connection]:
        """
        Create LDAP connection.

        If user_dn/password provided, binds as that user (for authentication).
        Otherwise uses service account for searches.
        """
        config = self._get_ldap_config()

        server_url = config.get('ldap_server')
        if not server_url:
            return None

        port = int(config.get('ldap_port') or 389)
        use_ssl = config.get('ldap_use_ssl', '').lower() == 'true'

        try:
            server = Server(server_url, port=port, use_ssl=use_ssl, get_info=ALL)

            if user_dn and password:
                # Bind as the user being authenticated
                conn = Connection(server, user=user_dn, password=password, auto_bind=True)
            else:
                # Bind as service account for searches
                bind_dn = config.get('ldap_bind_dn')
                bind_password = config.get('ldap_bind_password')
                if bind_dn and bind_password:
                    conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
                else:
                    # Anonymous bind
                    conn = Connection(server, auto_bind=True)

            return conn
        except LDAPSocketOpenError as e:
            logger.error(f"LDAP connection failed: {e}")
            return None
        except LDAPException as e:
            logger.error(f"LDAP error: {e}")
            return None

    def _find_user_dn(self, username: str) -> Optional[str]:
        """Find user's DN by searching with service account."""
        config = self._get_ldap_config()

        conn = self._get_ldap_connection()
        if not conn:
            return None

        try:
            user_base_dn = config.get('ldap_user_base_dn', '')
            user_filter = config.get('ldap_user_filter', '(sAMAccountName={username})')

            # Replace placeholder with actual username
            search_filter = user_filter.replace('{username}', username)

            conn.search(user_base_dn, search_filter, attributes=['distinguishedName', 'cn', 'mail', 'displayName'])

            if conn.entries:
                return str(conn.entries[0].entry_dn)
            return None
        finally:
            conn.unbind()

    def _get_user_groups(self, user_dn: str) -> List[str]:
        """Get list of groups the user belongs to."""
        config = self._get_ldap_config()

        conn = self._get_ldap_connection()
        if not conn:
            return []

        try:
            group_base_dn = config.get('ldap_group_base_dn', '')
            group_filter = config.get('ldap_group_filter', '(&(objectClass=group)(member={user_dn}))')

            # Replace placeholder with user's DN
            search_filter = group_filter.replace('{user_dn}', user_dn)

            conn.search(group_base_dn, search_filter, attributes=['cn', 'distinguishedName'])

            groups = []
            for entry in conn.entries:
                groups.append(str(entry.cn))

            return groups
        finally:
            conn.unbind()

    def _get_user_info(self, user_dn: str) -> Dict:
        """Get user's display name and email."""
        conn = self._get_ldap_connection()
        if not conn:
            return {}

        try:
            conn.search(user_dn, '(objectClass=*)', attributes=['cn', 'displayName', 'mail', 'givenName', 'sn'])

            if conn.entries:
                entry = conn.entries[0]
                return {
                    'display_name': str(entry.displayName) if hasattr(entry, 'displayName') and entry.displayName else str(entry.cn),
                    'email': str(entry.mail) if hasattr(entry, 'mail') and entry.mail else None,
                    'first_name': str(entry.givenName) if hasattr(entry, 'givenName') and entry.givenName else None,
                    'last_name': str(entry.sn) if hasattr(entry, 'sn') and entry.sn else None,
                }
            return {}
        finally:
            conn.unbind()

    def _map_groups_to_role(self, ldap_groups: List[str]) -> Tuple[str, Optional[str]]:
        """
        Map LDAP groups to application role and group.

        Returns:
            Tuple of (role, group_id)
            role: 'admin' or 'baseline_expert'
            group_id: 'server', 'telecom', 'network', 'desktop', or None
        """
        config = self._get_ldap_config()

        # Check admin groups first
        admin_groups_str = config.get('ldap_admin_groups', '')
        if admin_groups_str:
            admin_groups = [g.strip() for g in admin_groups_str.split(',')]
            for ldap_group in ldap_groups:
                if ldap_group in admin_groups:
                    return ('admin', None)

        # Check group mapping
        group_mapping_str = config.get('ldap_group_mapping', '{}')
        try:
            group_mapping = json.loads(group_mapping_str)
        except json.JSONDecodeError:
            group_mapping = {}

        # group_mapping format: {"LDAP-Group-Name": "app_group_id", ...}
        for ldap_group in ldap_groups:
            if ldap_group in group_mapping:
                return ('baseline_expert', group_mapping[ldap_group])

        # No matching group - default to baseline_expert with no group
        return ('baseline_expert', None)

    def _cache_user(self, username: str, password: str, full_name: str,
                    role: str, group_id: Optional[str], ldap_groups: List[str]):
        """Cache user credentials for offline authentication."""
        from database import User

        db = self.db_session_factory()
        try:
            # Hash password for cache
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Check if user exists
            user = db.query(User).filter(User.username == username).first()

            if user:
                # Update existing cached user
                user.password_hash = password_hash
                user.full_name = full_name
                user.role = role
                user.group_id = group_id
                user.last_login = datetime.utcnow()
                user.is_active = True
            else:
                # Create new cached user
                user = User(
                    username=username,
                    password_hash=password_hash,
                    full_name=full_name,
                    role=role,
                    group_id=group_id,
                    is_active=True,
                    created_by='ldap_sync',
                    last_login=datetime.utcnow()
                )
                db.add(user)

            db.commit()
            logger.info(f"Cached LDAP user: {username} (role={role}, group={group_id})")

        except Exception as e:
            logger.error(f"Failed to cache user {username}: {e}")
            db.rollback()
        finally:
            db.close()

    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        """
        Authenticate user via LDAP with offline fallback.

        Returns:
            Dict with user info on success, None on failure.
            {
                'username': str,
                'full_name': str,
                'role': str,
                'group_id': str or None,
                'auth_method': 'ldap' or 'cached'
            }
        """
        if not self.is_ldap_enabled():
            return None

        # Try LDAP authentication
        try:
            result = self._authenticate_ldap(username, password)
            if result:
                return result
        except Exception as e:
            logger.warning(f"LDAP authentication failed, trying cache: {e}")

        # Fall back to cached credentials
        return self._authenticate_cached(username, password)

    def _authenticate_ldap(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate directly against LDAP."""
        # Find user's DN
        user_dn = self._find_user_dn(username)
        if not user_dn:
            logger.info(f"LDAP user not found: {username}")
            return None

        # Try to bind as the user
        try:
            conn = self._get_ldap_connection(user_dn, password)
            if not conn:
                return None
            conn.unbind()
        except LDAPBindError:
            logger.info(f"LDAP bind failed for: {username}")
            return None

        # Get user info and groups
        user_info = self._get_user_info(user_dn)
        ldap_groups = self._get_user_groups(user_dn)

        # Map to role and group
        role, group_id = self._map_groups_to_role(ldap_groups)

        full_name = user_info.get('display_name', username)

        # Cache for offline use
        self._cache_user(username, password, full_name, role, group_id, ldap_groups)

        logger.info(f"LDAP authentication successful: {username} (role={role}, group={group_id})")

        return {
            'username': username,
            'full_name': full_name,
            'role': role,
            'group_id': group_id,
            'auth_method': 'ldap'
        }

    def _authenticate_cached(self, username: str, password: str) -> Optional[Dict]:
        """Authenticate using cached credentials (offline mode)."""
        from database import User

        config = self._get_ldap_config()
        cache_hours = int(config.get('ldap_cache_hours') or 168)  # Default 7 days

        db = self.db_session_factory()
        try:
            user = db.query(User).filter(
                User.username == username,
                User.is_active == True,
                User.created_by == 'ldap_sync'
            ).first()

            if not user:
                return None

            # Check cache expiry
            if user.last_login:
                cache_age = datetime.utcnow() - user.last_login
                if cache_age > timedelta(hours=cache_hours):
                    logger.info(f"Cached credentials expired for: {username}")
                    return None

            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                return None

            # Update last login
            user.last_login = datetime.utcnow()
            db.commit()

            logger.info(f"Cached authentication successful: {username}")

            return {
                'username': user.username,
                'full_name': user.full_name,
                'role': user.role,
                'group_id': user.group_id,
                'auth_method': 'cached'
            }
        finally:
            db.close()

    def test_connection(self) -> Dict:
        """Test LDAP connection and return status."""
        config = self._get_ldap_config()

        if not config.get('ldap_server'):
            return {'success': False, 'message': 'LDAP server not configured'}

        try:
            conn = self._get_ldap_connection()
            if conn:
                server_info = {
                    'server': config.get('ldap_server'),
                    'port': config.get('ldap_port', '389'),
                    'ssl': config.get('ldap_use_ssl', 'false')
                }
                conn.unbind()
                return {'success': True, 'message': 'Connection successful', 'server_info': server_info}
            else:
                return {'success': False, 'message': 'Failed to establish connection'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
