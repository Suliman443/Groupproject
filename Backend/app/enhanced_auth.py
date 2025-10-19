"""
Enhanced Authentication Module
Provides additional security layers for user authentication and session management
"""

# Constants for error messages
INVALID_CREDENTIALS_MSG = "Invalid credentials"
INVALID_TOKEN_USER_NOT_FOUND_MSG = "Invalid token - user not found"
AUTHENTICATION_FAILED_MSG = "Authentication failed"

import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, g, current_app
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app.extensions import db
from app.security import security_manager


class EnhancedAuthManager:
    """Enhanced authentication manager with additional security features"""
    
    def __init__(self):
        self.max_login_attempts = 5
        self.lockout_duration = 900  # 15 minutes
        self.session_timeout = 3600  # 1 hour
    
    def create_secure_tokens(self, user_id, additional_claims=None):
        """Create JWT tokens with enhanced security"""
        try:
            # Create additional claims for enhanced security
            claims = {
                'user_id': user_id,
                'login_time': int(time.time()),
                'ip_address': request.remote_addr,
                'user_agent_hash': hashlib.sha256(
                    request.headers.get('User-Agent', '').encode()
                ).hexdigest()[:16],
                'is_revoked': False
            }
            
            if additional_claims:
                claims.update(additional_claims)
            
            # Create tokens with shorter expiration for enhanced security
            access_token = create_access_token(
                identity=user_id,
                additional_claims=claims,
                expires_delta=timedelta(minutes=30)  # Shorter access token
            )
            
            refresh_token = create_refresh_token(
                identity=user_id,
                additional_claims=claims,
                expires_delta=timedelta(days=7)  # Longer refresh token
            )
            
            # Store session information
            self._store_session_info(user_id, claims)
            
            return access_token, refresh_token
            
        except Exception as e:
            security_manager.log_security_event('token_creation_error', user_id, {'error': str(e)})
            raise
    
    def validate_token_security(self, user_id, jwt_claims):
        """Validate token security claims"""
        try:
            # Check IP address consistency
            current_ip = request.remote_addr
            token_ip = jwt_claims.get('ip_address')
            
            if token_ip and token_ip != current_ip:
                security_manager.log_security_event('ip_address_mismatch', user_id, {
                    'token_ip': token_ip,
                    'current_ip': current_ip
                })
                return False
            
            # Check user agent consistency
            current_ua_hash = hashlib.sha256(
                request.headers.get('User-Agent', '').encode()
            ).hexdigest()[:16]
            token_ua_hash = jwt_claims.get('user_agent_hash')
            
            if token_ua_hash and token_ua_hash != current_ua_hash:
                security_manager.log_security_event('user_agent_mismatch', user_id, {
                    'token_ua': token_ua_hash,
                    'current_ua': current_ua_hash
                })
                return False
            
            # Check if token is revoked
            if jwt_claims.get('is_revoked', False):
                security_manager.log_security_event('revoked_token_usage', user_id)
                return False
            
            return True
            
        except Exception as e:
            security_manager.log_security_event('token_validation_error', user_id, {'error': str(e)})
            return False
    
    def _store_session_info(self, user_id, claims):
        """Store session information for security monitoring"""
        if security_manager.redis_client:
            session_key = f"session:{user_id}:{int(time.time())}"
            session_data = {
                'user_id': user_id,
                'login_time': claims['login_time'],
                'ip_address': claims['ip_address'],
                'user_agent_hash': claims['user_agent_hash'],
                'last_activity': int(time.time())
            }
            
            security_manager.redis_client.setex(
                session_key, 
                self.session_timeout, 
                str(session_data)
            )
    
    def revoke_user_tokens(self, user_id):
        """Revoke all tokens for a specific user"""
        try:
            if security_manager.redis_client:
                # Mark all sessions as revoked
                pattern = f"session:{user_id}:*"
                keys = security_manager.redis_client.keys(pattern)
                
                for key in keys:
                    session_data = security_manager.redis_client.get(key)
                    if session_data:
                        # Update session data to mark as revoked
                        updated_data = eval(session_data)  # In production, use proper JSON parsing
                        updated_data['is_revoked'] = True
                        security_manager.redis_client.setex(key, 300, str(updated_data))  # Keep for 5 minutes
                
                security_manager.log_security_event('user_tokens_revoked', user_id)
                return True
                
        except Exception as e:
            security_manager.log_security_event('token_revocation_error', user_id, {'error': str(e)})
            return False
    
    def validate_password_strength(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    def generate_secure_password(self, length=16):
        """Generate a secure random password"""
        characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password
    
    def create_user_with_enhanced_security(self, email, password, fullname, role='user'):
        """Create user with enhanced security measures"""
        try:
            # Validate password strength
            is_strong, message = self.validate_password_strength(password)
            if not is_strong:
                return None, message
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                return None, "Email already registered"
            
            # Generate secure password hash with additional salt
            salt = secrets.token_hex(16)
            password_with_salt = password + salt
            hashed_password = generate_password_hash(password_with_salt, method='pbkdf2:sha256', salt_length=32)
            
            # Create user with enhanced security
            new_user = User(
                email=email,
                hashed_password=f"{salt}:{hashed_password}",  # Store salt with hash
                fullname=fullname,
                role=role
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Log successful user creation
            security_manager.log_security_event('user_created', new_user.id, {
                'email': email,
                'role': role
            })
            
            return new_user, "User created successfully"
            
        except Exception as e:
            db.session.rollback()
            security_manager.log_security_event('user_creation_error', details={'error': str(e)})
            return None, "Error creating user"
    
    def authenticate_user_with_enhanced_security(self, email, password):
        """Authenticate user with enhanced security checks"""
        try:
            # Check if account is locked
            if security_manager.is_account_locked(email):
                security_manager.log_security_event('locked_account_login_attempt', details={'email': email})
                return None, "Account temporarily locked due to multiple failed attempts"
            
            # Find user
            user = User.query.filter_by(email=email).first()
            if not user:
                security_manager.track_login_attempt(email, success=False)
                return None, "Invalid credentials"
            
            # Extract salt and hash from stored password
            try:
                salt, stored_hash = user.hashed_password.split(':', 1)
                password_with_salt = password + salt
                
                if not check_password_hash(stored_hash, password_with_salt):
                    security_manager.track_login_attempt(email, success=False)
                    security_manager.log_security_event('failed_login_attempt', user.id, {'email': email})
                    return None, INVALID_CREDENTIALS_MSG
                
            except ValueError:
                # Handle old password format (backward compatibility)
                if not check_password_hash(user.hashed_password, password):
                    security_manager.track_login_attempt(email, success=False)
                    security_manager.log_security_event('failed_login_attempt', user.id, {'email': email})
                    return None, INVALID_CREDENTIALS_MSG
            
            # Successful authentication
            security_manager.track_login_attempt(email, success=True)
            security_manager.log_security_event('successful_login', user.id, {'email': email})
            
            return user, "Authentication successful"
            
        except Exception as e:
            security_manager.log_security_event('authentication_error', details={'error': str(e)})
            return None, "Authentication error"


# Global enhanced auth manager
enhanced_auth = EnhancedAuthManager()


def enhanced_login_required(f):
    """Enhanced login decorator with additional security checks"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            jwt_claims = get_jwt()
            
            # Get user
            current_user = User.query.get(current_user_id)
            if not current_user:
                security_manager.log_security_event('invalid_token_user_not_found', current_user_id)
                return jsonify({'message': INVALID_TOKEN_USER_NOT_FOUND_MSG}), 401
            
            # Validate token security
            if not enhanced_auth.validate_token_security(current_user_id, jwt_claims):
                return jsonify({'message': 'Token security validation failed'}), 401
            
            # Store current user in Flask g
            g.current_user = current_user
            
            return f(*args, **kwargs)
            
        except Exception as e:
            security_manager.log_security_event('enhanced_auth_error', details={'error': str(e)})
            return jsonify({'message': AUTHENTICATION_FAILED_MSG}), 401
    
    return decorated


def admin_required_enhanced(f):
    """Enhanced admin decorator with security logging"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                security_manager.log_security_event('admin_access_user_not_found', current_user_id)
                return jsonify({'message': INVALID_TOKEN_USER_NOT_FOUND_MSG}), 401
            
            if current_user.role != 'admin':
                security_manager.log_security_event('unauthorized_admin_access', current_user_id, {
                    'user_role': current_user.role,
                    'endpoint': request.endpoint
                })
                return jsonify({'message': 'Admin access required'}), 403
            
            g.current_user = current_user
            return f(*args, **kwargs)
            
        except Exception as e:
            security_manager.log_security_event('admin_validation_error', details={'error': str(e)})
            return jsonify({'message': AUTHENTICATION_FAILED_MSG}), 401
    
    return decorated


def organizer_required_enhanced(f):
    """Enhanced organizer decorator with security logging"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                security_manager.log_security_event('organizer_access_user_not_found', current_user_id)
                return jsonify({'message': INVALID_TOKEN_USER_NOT_FOUND_MSG}), 401
            
            if current_user.role not in ['organizer', 'admin']:
                security_manager.log_security_event('unauthorized_organizer_access', current_user_id, {
                    'user_role': current_user.role,
                    'endpoint': request.endpoint
                })
                return jsonify({'message': 'Organizer access required'}), 403
            
            g.current_user = current_user
            return f(*args, **kwargs)
            
        except Exception as e:
            security_manager.log_security_event('organizer_validation_error', details={'error': str(e)})
            return jsonify({'message': AUTHENTICATION_FAILED_MSG}), 401
    
    return decorated


def session_timeout_required(f):
    """Decorator to enforce session timeout"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            current_user_id = get_jwt_identity()
            jwt_claims = get_jwt()
            
            # Check session timeout
            login_time = jwt_claims.get('login_time', 0)
            current_time = int(time.time())
            
            if current_time - login_time > enhanced_auth.session_timeout:
                security_manager.log_security_event('session_timeout', current_user_id)
                return jsonify({'message': 'Session expired'}), 401
            
            return f(*args, **kwargs)
            
        except Exception as e:
            security_manager.log_security_event('session_timeout_error', details={'error': str(e)})
            return jsonify({'message': 'Session validation failed'}), 401
    
    return decorated
