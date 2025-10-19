"""
Security Enhancement Module
Provides additional security layers including field encryption, rate limiting, and enhanced authentication
"""

import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
from flask import request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from app.extensions import db
from app.models.user import User

class SecurityManager:
    """Centralized security management for the application"""
    
    def __init__(self, app=None):
        self.app = app
        self.encryption_key = None
        self.rate_limiter = None
        self.redis_client = None
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security components with Flask app"""
        self.app = app
        
        # Initialize encryption
        self._init_encryption()
        
        # Initialize rate limiting
        self._init_rate_limiting()
        
        # Initialize Redis for session management
        self._init_redis()
    
    def _init_encryption(self):
        """Initialize encryption system"""
        # Generate or load encryption key
        key_file = os.path.join(self.app.config.get('BASE_DIR', ''), 'encryption.key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            # Generate new key
            password = self.app.config.get('SECRET_KEY', 'default-secret').encode()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self.encryption_key = base64.urlsafe_b64encode(kdf.derive(password))
            
            # Save key to file
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
    
    def _init_rate_limiting(self):
        """Initialize rate limiting"""
        try:
            self.rate_limiter = Limiter(
                self.app,
                key_func=get_remote_address,
                default_limits=["1000 per hour"]
            )
        except Exception as e:
            print(f"Rate limiting initialization failed: {e}")
            self.rate_limiter = None
    
    def _init_redis(self):
        """Initialize Redis for session management"""
        try:
            self.redis_client = redis.Redis(
                host='localhost',
                port=6379,
                db=0,
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
        except Exception as e:
            print(f"Redis initialization failed: {e}")
            self.redis_client = None
    
    def encrypt_field(self, data):
        """Encrypt sensitive data"""
        if not data:
            return data
        
        try:
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"Encryption failed: {e}")
            return data
    
    def decrypt_field(self, encrypted_data):
        """Decrypt sensitive data"""
        if not encrypted_data:
            return encrypted_data
        
        try:
            fernet = Fernet(self.encryption_key)
            decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = fernet.decrypt(decoded_data)
            return decrypted_data.decode()
        except Exception as e:
            print(f"Decryption failed: {e}")
            return encrypted_data
    
    def hash_sensitive_data(self, data):
        """Create irreversible hash of sensitive data"""
        if not data:
            return data
        
        salt = secrets.token_hex(16)
        hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
        return f"{salt}:{hash_obj.hex()}"
    
    def verify_hash(self, data, hash_value):
        """Verify data against hash"""
        if not data or not hash_value:
            return False
        
        try:
            salt, stored_hash = hash_value.split(':')
            hash_obj = hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000)
            return hash_obj.hex() == stored_hash
        except:
            return False
    
    def track_login_attempt(self, email, success=False):
        """Track login attempts for security monitoring"""
        if not self.redis_client:
            return
        
        key = f"login_attempts:{email}"
        timestamp = int(time.time())
        
        if success:
            # Clear failed attempts on successful login
            self.redis_client.delete(key)
        else:
            # Track failed attempt
            self.redis_client.lpush(key, timestamp)
            self.redis_client.expire(key, 3600)  # Expire after 1 hour
    
    def is_account_locked(self, email):
        """Check if account is locked due to failed attempts"""
        if not self.redis_client:
            return False
        
        key = f"login_attempts:{email}"
        attempts = self.redis_client.lrange(key, 0, 4)  # Check last 5 attempts
        
        if len(attempts) >= 5:
            # Check if attempts are within last 15 minutes
            recent_attempts = [int(t) for t in attempts if int(t) > (int(time.time()) - 900)]
            return len(recent_attempts) >= 5
        
        return False
    
    def log_security_event(self, event_type, user_id=None, details=None):
        """Log security events for audit trail"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': get_remote_address(),
            'user_agent': request.headers.get('User-Agent', ''),
            'details': details or {}
        }
        
        # In production, this should be logged to a secure audit system
        print(f"SECURITY_EVENT: {log_entry}")
        
        # Store in Redis for temporary audit trail
        if self.redis_client:
            audit_key = f"audit_log:{int(time.time())}"
            self.redis_client.setex(audit_key, 86400, str(log_entry))  # Keep for 24 hours


# Global security manager instance
security_manager = SecurityManager()


def enhanced_token_required(f):
    """Enhanced token validation with additional security checks"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
            
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                security_manager.log_security_event('invalid_token_user_not_found', current_user_id)
                return jsonify({'message': 'Invalid token - user not found'}), 401
            
            # Check for suspicious activity
            jwt_data = get_jwt()
            if jwt_data.get('is_revoked', False):
                security_manager.log_security_event('revoked_token_usage', current_user_id)
                return jsonify({'message': 'Token has been revoked'}), 401
            
            # Store current user in Flask g for access in route
            g.current_user = current_user
            
            return f(*args, **kwargs)
        except Exception as e:
            security_manager.log_security_event('token_validation_error', details={'error': str(e)})
            return jsonify({'message': 'Token is invalid or expired'}), 401
    
    return decorated


def rate_limit_by_user(f):
    """Rate limiting decorator that considers user authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if security_manager.rate_limiter:
            # Different limits for authenticated vs anonymous users
            if hasattr(g, 'current_user') and g.current_user:
                limit = "1000 per hour"  # Higher limit for authenticated users
            else:
                limit = "100 per hour"   # Lower limit for anonymous users
            
            try:
                security_manager.rate_limiter.limit(limit)(f)(*args, **kwargs)
            except Exception as e:
                return jsonify({'message': 'Rate limit exceeded'}), 429
        
        return f(*args, **kwargs)
    
    return decorated


def admin_required_enhanced(f):
    """Enhanced admin role validation with security logging"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
            
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                security_manager.log_security_event('admin_access_user_not_found', current_user_id)
                return jsonify({'message': 'Invalid token - user not found'}), 401
            
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
            return jsonify({'message': 'Token is invalid or expired'}), 401
    
    return decorated


def input_sanitization_required(f):
    """Decorator to sanitize and validate input data"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Sanitize JSON input
        if request.is_json:
            data = request.get_json()
            sanitized_data = security_manager.sanitize_input(data)
            request._cached_json = sanitized_data
        
        return f(*args, **kwargs)
    
    return decorated


def SecurityManager.sanitize_input(self, data):
    """Sanitize input data to prevent injection attacks"""
    if isinstance(data, dict):
        return {key: self.sanitize_input(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [self.sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Remove potentially dangerous characters
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '|', '`']
        for char in dangerous_chars:
            data = data.replace(char, '')
        return data.strip()
    else:
        return data


def audit_log_required(f):
    """Decorator to log all access to sensitive endpoints"""
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = getattr(g, 'current_user', None)
        user_id = user_id.id if user_id else None
        
        security_manager.log_security_event(
            'endpoint_access',
            user_id,
            {
                'endpoint': request.endpoint,
                'method': request.method,
                'path': request.path
            }
        )
        
        return f(*args, **kwargs)
    
    return decorated


# Database field encryption mixins
class EncryptedFieldMixin:
    """Mixin to add encryption capabilities to SQLAlchemy models"""
    
    def encrypt_field(self, field_name, value):
        """Encrypt a specific field"""
        if value:
            encrypted_value = security_manager.encrypt_field(str(value))
            setattr(self, f"{field_name}_encrypted", encrypted_value)
            setattr(self, field_name, None)  # Clear plaintext
    
    def decrypt_field(self, field_name):
        """Decrypt a specific field"""
        encrypted_value = getattr(self, f"{field_name}_encrypted", None)
        if encrypted_value:
            return security_manager.decrypt_field(encrypted_value)
        return getattr(self, field_name, None)


# Enhanced User model with encryption
class SecureUser(User, EncryptedFieldMixin):
    """Enhanced User model with field encryption"""
    
    # Additional encrypted fields
    email_encrypted = db.Column(db.Text)
    fullname_encrypted = db.Column(db.Text)
    
    def set_email(self, email):
        """Set encrypted email"""
        self.encrypt_field('email', email)
    
    def get_email(self):
        """Get decrypted email"""
        return self.decrypt_field('email')
    
    def set_fullname(self, fullname):
        """Set encrypted fullname"""
        self.encrypt_field('fullname', fullname)
    
    def get_fullname(self):
        """Get decrypted fullname"""
        return self.decrypt_field('fullname')


# Security middleware
def init_security_middleware(app):
    """Initialize security middleware for the Flask app"""
    
    @app.before_request
    def security_headers():
        """Add security headers to all responses"""
        from flask import make_response
        
        @app.after_request
        def after_request(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'"
            return response
    
    @app.before_request
    def check_account_lockout():
        """Check if user account is locked due to failed attempts"""
        if request.endpoint == 'auth.login':
            email = request.get_json().get('email') if request.is_json else None
            if email and security_manager.is_account_locked(email):
                security_manager.log_security_event('locked_account_access_attempt', details={'email': email})
                return jsonify({'message': 'Account temporarily locked due to multiple failed attempts'}), 423
    
    @app.errorhandler(429)
    def handle_rate_limit(e):
        """Handle rate limit exceeded errors"""
        security_manager.log_security_event('rate_limit_exceeded', details={
            'ip': get_remote_address(),
            'endpoint': request.endpoint
        })
        return jsonify({'message': 'Rate limit exceeded. Please try again later.'}), 429



