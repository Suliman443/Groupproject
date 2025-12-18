"""
Enhanced Authentication Routes
Implements additional security layers for user authentication
"""

from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from app.models import User
from app.extensions import db
from app.enhanced_auth import enhanced_auth, enhanced_login_required
from app.security import security_manager, rate_limit_by_user, audit_log_required
from app.auth_utils import revoke_all_tokens_for_user

# Create enhanced auth blueprint
enhanced_auth_bp = Blueprint('enhanced_auth', __name__)


@enhanced_auth_bp.route('/secure-signup', methods=['POST'])
@rate_limit_by_user
@audit_log_required
def secure_signup():
    """Enhanced user registration with security validation"""
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['email', 'password', 'fullname']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'message': f'{field} is required'}), 400
    
    # Validate email format
    email = data['email'].lower().strip()
    if '@' not in email or '.' not in email.split('@')[1]:
        return jsonify({'message': 'Invalid email format'}), 400
    
    # Create user with enhanced security
    user, message = enhanced_auth.create_user_with_enhanced_security(
        email=email,
        password=data['password'],
        fullname=data['fullname'],
        role=data.get('role', 'user')
    )
    
    if not user:
        return jsonify({'message': message}), 400
    
    # Create secure tokens
    try:
        access_token, refresh_token = enhanced_auth.create_secure_tokens(user.id)
        
        return jsonify({
            'message': 'User created successfully',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'fullname': user.fullname,
                'role': user.role
            }
        }), 201
        
    except Exception as e:
        security_manager.log_security_event('token_creation_error', user.id, {'error': str(e)})
        return jsonify({'message': 'User created but token generation failed'}), 201


@enhanced_auth_bp.route('/secure-login', methods=['POST'])
@rate_limit_by_user
@audit_log_required
def secure_login():
    """Enhanced user login with security monitoring"""
    data = request.get_json()
    
    if not all(k in data for k in ['email', 'password']):
        return jsonify({'message': 'Email and password are required'}), 400
    
    email = data['email'].lower().strip()
    password = data['password']
    
    # Authenticate user with enhanced security
    user, message = enhanced_auth.authenticate_user_with_enhanced_security(email, password)
    
    if not user:
        return jsonify({'message': message}), 401
    
    # Create secure tokens
    try:
        access_token, refresh_token = enhanced_auth.create_secure_tokens(user.id)
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'fullname': user.fullname,
                'role': user.role
            }
        }), 200
        
    except Exception as e:
        security_manager.log_security_event('login_token_error', user.id, {'error': str(e)})
        return jsonify({'message': 'Login successful but token generation failed'}), 200


@enhanced_auth_bp.route('/secure-refresh', methods=['POST'])
@jwt_required(refresh=True)
@audit_log_required
def secure_refresh():
    """Enhanced token refresh with security validation"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            security_manager.log_security_event('refresh_user_not_found', current_user_id)
            return jsonify({'message': 'User not found'}), 404
        
        # Create new access token with enhanced security
        access_token, _ = enhanced_auth.create_secure_tokens(current_user_id)
        
        return jsonify({
            'access_token': access_token
        }), 200
        
    except Exception as e:
        security_manager.log_security_event('refresh_error', details={'error': str(e)})
        return jsonify({'message': 'Token refresh failed'}), 401


@enhanced_auth_bp.route('/secure-profile', methods=['GET'])
@enhanced_login_required
@audit_log_required
def get_secure_profile():
    """Get user profile with enhanced security"""
    current_user = g.current_user
    
    return jsonify({
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'fullname': current_user.fullname,
            'role': current_user.role
        }
    }), 200


@enhanced_auth_bp.route('/change-password', methods=['POST'])
@enhanced_login_required
@audit_log_required
def change_password():
    """Change user password with enhanced security"""
    data = request.get_json()
    current_user = g.current_user
    
    if not all(k in data for k in ['current_password', 'new_password']):
        return jsonify({'message': 'Current password and new password are required'}), 400
    
    # Verify current password
    try:
        salt, stored_hash = current_user.hashed_password.split(':', 1)
        password_with_salt = data['current_password'] + salt
        
        if not check_password_hash(stored_hash, password_with_salt):
            security_manager.log_security_event('wrong_password_change_attempt', current_user.id)
            return jsonify({'message': 'Current password is incorrect'}), 400
            
    except ValueError:
        # Handle old password format
        if not check_password_hash(current_user.hashed_password, data['current_password']):
            security_manager.log_security_event('wrong_password_change_attempt', current_user.id)
            return jsonify({'message': 'Current password is incorrect'}), 400
    
    # Validate new password strength
    is_strong, message = enhanced_auth.validate_password_strength(data['new_password'])
    if not is_strong:
        return jsonify({'message': message}), 400
    
    # Update password with enhanced security
    try:
        salt = secrets.token_hex(16)
        password_with_salt = data['new_password'] + salt
        hashed_password = generate_password_hash(password_with_salt, method='pbkdf2:sha256', salt_length=32)
        
        current_user.hashed_password = f"{salt}:{hashed_password}"
        db.session.commit()
        
        # Revoke all existing tokens for security
        enhanced_auth.revoke_user_tokens(current_user.id)
        
        security_manager.log_security_event('password_changed', current_user.id)
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        security_manager.log_security_event('password_change_error', current_user.id, {'error': str(e)})
        return jsonify({'message': 'Error changing password'}), 500


@enhanced_auth_bp.route('/logout', methods=['POST'])
@enhanced_login_required
@audit_log_required
def secure_logout():
    """Enhanced logout with token revocation"""
    current_user = g.current_user
    
    try:
        # Revoke all tokens for the user
        enhanced_auth.revoke_user_tokens(current_user.id)
        
        security_manager.log_security_event('user_logout', current_user.id)
        
        return jsonify({'message': 'Logged out successfully'}), 200
        
    except Exception as e:
        security_manager.log_security_event('logout_error', current_user.id, {'error': str(e)})
        return jsonify({'message': 'Logout completed with warnings'}), 200


@enhanced_auth_bp.route('/generate-secure-password', methods=['GET'])
@enhanced_login_required
def generate_secure_password():
    """Generate a secure password for user"""
    try:
        secure_password = enhanced_auth.generate_secure_password()
        
        return jsonify({
            'password': secure_password,
            'message': 'Secure password generated'
        }), 200
        
    except Exception as e:
        security_manager.log_security_event('password_generation_error', details={'error': str(e)})
        return jsonify({'message': 'Error generating password'}), 500


@enhanced_auth_bp.route('/security-status', methods=['GET'])
@enhanced_login_required
def get_security_status():
    """Get user security status and recommendations"""
    current_user = g.current_user
    
    try:
        # Check if account is locked
        is_locked = security_manager.is_account_locked(current_user.email)
        
        # Get recent security events
        recent_events = []
        if security_manager.redis_client:
            pattern = "audit_log:*"
            keys = security_manager.redis_client.keys(pattern)
            for key in sorted(keys, reverse=True)[:5]:  # Last 5 events
                event_data = security_manager.redis_client.get(key)
                if event_data:
                    recent_events.append(eval(event_data))  # In production, use proper JSON parsing
        
        return jsonify({
            'user_id': current_user.id,
            'account_locked': is_locked,
            'recent_security_events': recent_events,
            'security_recommendations': [
                'Use strong passwords with mixed characters',
                'Enable two-factor authentication if available',
                'Regularly review account activity',
                'Log out from shared devices'
            ]
        }), 200
        
    except Exception as e:
        security_manager.log_security_event('security_status_error', current_user.id, {'error': str(e)})
        return jsonify({'message': 'Error retrieving security status'}), 500


# Import required modules
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
