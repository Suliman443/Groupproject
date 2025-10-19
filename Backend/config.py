import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'dev.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Enhanced Security Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_urlsafe(32)
    
    # JWT Configuration with Enhanced Security
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)  # Shorter access token
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)     # Shorter refresh token
    JWT_ALGORITHM = 'HS256'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'"
    }
    
    # Rate Limiting Configuration
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
    RATELIMIT_DEFAULT = "1000 per hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # Password Security
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPERCASE = True
    PASSWORD_REQUIRE_LOWERCASE = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL_CHARS = True
    
    # Session Security
    SESSION_TIMEOUT = 3600  # 1 hour
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = 900  # 15 minutes
    
    # Encryption Configuration
    ENCRYPTION_KEY_FILE = os.path.join(BASE_DIR, 'encryption.key')
    
    # Audit Logging
    AUDIT_LOG_ENABLED = True
    AUDIT_LOG_RETENTION_DAYS = 30
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:4322').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_HEADERS = ['Content-Type', 'Authorization']
    
    # File Upload Security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
    
    # Database Security
    DATABASE_ENCRYPTION_ENABLED = True
    DATABASE_BACKUP_ENCRYPTION = True
    
    # API Security
    API_RATE_LIMIT_PER_USER = "1000 per hour"
    API_RATE_LIMIT_PER_IP = "100 per hour"
    
    # Security Monitoring
    SECURITY_MONITORING_ENABLED = True
    SUSPICIOUS_ACTIVITY_THRESHOLD = 5
    
    @staticmethod
    def init_app(app):
        """Initialize application with security configurations"""
        # Set up security headers
        @app.after_request
        def after_request(response):
            for header, value in Config.SECURITY_HEADERS.items():
                response.headers[header] = value
            return response
        
        # Configure session security
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=Config.SESSION_TIMEOUT)
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


class DevelopmentConfig(Config):
    """Development configuration with relaxed security for testing"""
    DEBUG = True
    TESTING = False
    
    # Relaxed security for development
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    SESSION_TIMEOUT = 86400  # 24 hours
    MAX_LOGIN_ATTEMPTS = 10
    
    # Development-specific settings
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Production configuration with enhanced security"""
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)
    SESSION_TIMEOUT = 1800  # 30 minutes
    
    # Production database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://user:password@localhost/event_management'
    
    # Production security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Enhanced monitoring
    SECURITY_MONITORING_ENABLED = True
    AUDIT_LOG_ENABLED = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # In-memory database for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable security features for testing
    SECURITY_MONITORING_ENABLED = False
    AUDIT_LOG_ENABLED = False
    MAX_LOGIN_ATTEMPTS = 100


# Configuration mapping
config_mapping = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}