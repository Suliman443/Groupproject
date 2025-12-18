"""
Authentication Utilities Module

Provides unified authentication decorators with full security enforcement:
- JWT token validation
- Token blocklist checking (revocation)
- IP address binding validation
- User agent (device) binding validation
- Session timeout enforcement
- Role-based access control
"""

from functools import wraps
from flask import jsonify, request, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from app.models.user import User

# Import security manager (lazy import to avoid circular dependency)
_security_manager = None


def _get_security_manager():
    """Lazy load security manager to avoid circular imports"""
    global _security_manager
    if _security_manager is None:
        from app.security import security_manager
        _security_manager = security_manager
    return _security_manager


# Configuration for session security
SESSION_TIMEOUT = 3600  # 1 hour default session timeout
ENFORCE_IP_BINDING = True  # Enforce IP address binding when present in token
ENFORCE_DEVICE_BINDING = True  # Enforce user agent binding when present in token


def token_required(f):
    """
    Unified decorator to require valid JWT token with full security enforcement.

    Security checks performed:
    1. JWT token validity
    2. User existence
    3. Token blocklist (individual token revocation)
    4. User-wide token revocation
    5. IP address binding (if token contains ip_address claim)
    6. Device/user-agent binding (if token contains user_agent_hash claim)
    7. Session timeout

    Usage:
        @app.route('/protected')
        @token_required
        def protected_route(current_user):
            return jsonify({'user': current_user.email})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        security_manager = _get_security_manager()

        try:
            # Verify JWT token
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            jwt_claims = get_jwt()

            # Get user from database
            current_user = User.query.get(current_user_id)

            if not current_user:
                security_manager.log_security_event('invalid_token_user_not_found', current_user_id)
                return jsonify({'message': 'Invalid token - user not found'}), 401

            # Perform unified session security validation
            is_valid, error_message = security_manager.validate_session_security(
                current_user_id,
                jwt_claims,
                session_timeout=SESSION_TIMEOUT
            )

            if not is_valid:
                return jsonify({'message': error_message}), 401

            # Store current user in Flask g for access in route
            g.current_user = current_user

            return f(current_user=current_user, *args, **kwargs)

        except Exception as e:
            security_manager.log_security_event('token_validation_error', details={'error': str(e)})
            return jsonify({'message': 'Token is invalid or expired'}), 401

    return decorated


def admin_required(f):
    """
    Decorator to require admin role with full security enforcement.

    Performs all security checks from token_required plus admin role verification.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        security_manager = _get_security_manager()

        try:
            # Verify JWT token
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            jwt_claims = get_jwt()

            # Get user from database
            current_user = User.query.get(current_user_id)

            if not current_user:
                security_manager.log_security_event('admin_access_user_not_found', current_user_id)
                return jsonify({'message': 'Invalid token - user not found'}), 401

            # Perform unified session security validation
            is_valid, error_message = security_manager.validate_session_security(
                current_user_id,
                jwt_claims,
                session_timeout=SESSION_TIMEOUT
            )

            if not is_valid:
                return jsonify({'message': error_message}), 401

            # Check admin role
            if current_user.role != 'admin':
                security_manager.log_security_event('unauthorized_admin_access', current_user_id, {
                    'user_role': current_user.role,
                    'endpoint': request.endpoint
                })
                return jsonify({'message': 'Admin access required'}), 403

            # Store current user in Flask g
            g.current_user = current_user

            return f(current_user=current_user, *args, **kwargs)

        except Exception as e:
            security_manager.log_security_event('admin_validation_error', details={'error': str(e)})
            return jsonify({'message': 'Token is invalid or expired'}), 401

    return decorated


def organizer_required(f):
    """
    Decorator to require organizer role with full security enforcement.

    Performs all security checks from token_required plus organizer role verification.
    Allows both 'organizer' and 'admin' roles.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        security_manager = _get_security_manager()

        try:
            # Verify JWT token
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            jwt_claims = get_jwt()

            # Get user from database
            current_user = User.query.get(current_user_id)

            if not current_user:
                security_manager.log_security_event('organizer_access_user_not_found', current_user_id)
                return jsonify({'message': 'Invalid token - user not found'}), 401

            # Perform unified session security validation
            is_valid, error_message = security_manager.validate_session_security(
                current_user_id,
                jwt_claims,
                session_timeout=SESSION_TIMEOUT
            )

            if not is_valid:
                return jsonify({'message': error_message}), 401

            # Check organizer role (allow admin as well)
            if current_user.role not in ['organizer', 'admin']:
                security_manager.log_security_event('unauthorized_organizer_access', current_user_id, {
                    'user_role': current_user.role,
                    'endpoint': request.endpoint
                })
                return jsonify({'message': 'Organizer access required'}), 403

            # Store current user in Flask g
            g.current_user = current_user

            return f(current_user=current_user, *args, **kwargs)

        except Exception as e:
            security_manager.log_security_event('organizer_validation_error', details={'error': str(e)})
            return jsonify({'message': 'Token is invalid or expired'}), 401

    return decorated


def get_current_user():
    """
    Get current authenticated user from JWT token.

    Returns:
        User object if authenticated, None otherwise
    """
    try:
        current_user_id = get_jwt_identity()
        return User.query.get(current_user_id)
    except:
        return None


def revoke_current_token():
    """
    Revoke the current JWT token by adding it to the blocklist.

    Should be called during logout to immediately invalidate the token.

    Returns:
        bool: True if successful, False otherwise
    """
    security_manager = _get_security_manager()

    try:
        jwt_claims = get_jwt()
        jti = jwt_claims.get('jti')

        if jti:
            # Calculate remaining TTL from token expiry
            exp = jwt_claims.get('exp', 0)
            current_time = __import__('time').time()
            expires_in = max(int(exp - current_time), 0) + 60  # Add 60s buffer

            return security_manager.add_token_to_blocklist(jti, expires_in)

        return False

    except Exception as e:
        security_manager.log_security_event('token_revocation_error', details={'error': str(e)})
        return False


def revoke_all_tokens_for_user(user_id):
    """
    Revoke all tokens for a specific user.

    Should be called during:
    - Password change
    - Security breach detection
    - Admin-initiated session termination

    Args:
        user_id: The user ID whose tokens should be revoked

    Returns:
        bool: True if successful, False otherwise
    """
    security_manager = _get_security_manager()
    return security_manager.revoke_all_user_tokens(user_id)