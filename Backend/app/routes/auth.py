import hashlib
import time
from datetime import timedelta
from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, get_jwt
)
from app.models import User  # Import from models package
from app.extensions import db
from app.auth_utils import token_required, revoke_current_token, revoke_all_tokens_for_user
from app.security import security_manager, input_sanitization_required

auth_bp = Blueprint('auth', __name__)


def create_secure_access_token(user_id):
    """Create access token with security claims for IP/device binding."""
    additional_claims = {
        'user_id': user_id,
        'login_time': int(time.time()),
        'ip_address': request.remote_addr,
        'user_agent_hash': hashlib.sha256(
            request.headers.get('User-Agent', '').encode()
        ).hexdigest()[:16],
        'is_revoked': False
    }

    return create_access_token(
        identity=user_id,
        additional_claims=additional_claims,
        expires_delta=timedelta(hours=1)  # 1 hour access token
    )


def create_secure_refresh_token(user_id):
    """Create refresh token with security claims."""
    additional_claims = {
        'user_id': user_id,
        'login_time': int(time.time()),
        'ip_address': request.remote_addr,
        'user_agent_hash': hashlib.sha256(
            request.headers.get('User-Agent', '').encode()
        ).hexdigest()[:16],
        'is_revoked': False
    }

    return create_refresh_token(
        identity=user_id,
        additional_claims=additional_claims,
        expires_delta=timedelta(days=7)  # 7 day refresh token
    )

@auth_bp.route('/signup', methods=['POST'])
@input_sanitization_required
def signup():
    data = request.get_json()

    # Validate required fields
    if not all(k in data for k in ['email', 'password', 'fullname']):
        return jsonify({'message': 'Missing required fields'}), 400

    # Check if user already exists using new search method
    existing_user = User.find_by_email(data['email'])
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400

    # Determine role (default to 'user', but allow 'organizer' if specified)
    role = data.get('role', 'user')
    if role not in ['user', 'organizer']:
        role = 'user'

    # Create new user with enhanced security
    new_user = User(
        email=data['email'],
        fullname=data['fullname'],
        role=role
    )

    # Set password using enhanced security hashing
    new_user.set_password_enhanced(data['password'])

    try:
        db.session.add(new_user)
        db.session.commit()

        # Log successful registration
        security_manager.log_security_event('user_registration', new_user.id, {
            'email': data['email'],
            'role': role
        })

        return jsonify({
            'message': f'{role.capitalize()} created successfully',
            'user': {
                'email': new_user.email,
                'fullname': new_user.fullname,
                'role': new_user.role
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        security_manager.log_security_event('user_registration_failed', details={
            'email': data.get('email'),
            'error': str(e)
        })
        return jsonify({'message': 'Error creating user'}), 500

@auth_bp.route('/organizer/signup', methods=['POST'])
@input_sanitization_required
def organizer_signup():
    """Dedicated endpoint for organizer registration"""
    data = request.get_json()

    # Validate required fields
    if not all(k in data for k in ['email', 'password', 'fullname']):
        return jsonify({'message': 'Missing required fields'}), 400

    # Check if user already exists using new search method
    existing_user = User.find_by_email(data['email'])
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400

    # Create new organizer with enhanced security
    new_organizer = User(
        email=data['email'],
        fullname=data['fullname'],
        role='organizer'
    )

    # Set password using enhanced security hashing
    new_organizer.set_password_enhanced(data['password'])

    try:
        db.session.add(new_organizer)
        db.session.commit()

        # Log successful organizer registration
        security_manager.log_security_event('organizer_registration', new_organizer.id, {
            'email': data['email']
        })

        return jsonify({
            'message': 'Organizer account created successfully',
            'user': {
                'email': new_organizer.email,
                'fullname': new_organizer.fullname,
                'role': new_organizer.role
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        security_manager.log_security_event('organizer_registration_failed', details={
            'email': data.get('email'),
            'error': str(e)
        })
        return jsonify({'message': 'Error creating organizer account'}), 500

@auth_bp.route('/login', methods=['POST'])
@input_sanitization_required
def login():
    data = request.get_json()

    if not all(k in data for k in ['email', 'password']):
        return jsonify({'message': 'Missing email or password'}), 400

    # Check for account lockout
    if security_manager.is_account_locked(data['email']):
        security_manager.log_security_event('locked_account_login_attempt', details={
            'email': data['email']
        })
        return jsonify({'message': 'Account temporarily locked due to multiple failed attempts'}), 423

    # Find user using new search method (works with encrypted emails)
    user = User.find_by_email(data['email'])

    # Also try legacy method for users not yet migrated
    if not user:
        user = User.find_by_email_legacy(data['email'])

    if user and user.check_password(data['password']):
        # Migrate user if not already migrated
        if not user.encryption_migrated:
            try:
                user.migrate_to_encrypted()
                db.session.commit()
            except Exception as e:
                # Log but don't fail login
                security_manager.log_security_event('migration_failed_on_login', user.id, {
                    'error': str(e)
                })

        # Track successful login
        security_manager.track_login_attempt(data['email'], success=True)
        security_manager.log_security_event('successful_login', user.id, {
            'email': data['email'],
            'ip_address': request.remote_addr
        })

        # Create secure JWT tokens with IP/device binding
        access_token = create_secure_access_token(user.id)
        refresh_token = create_secure_refresh_token(user.id)

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

    # Track failed login attempt
    security_manager.track_login_attempt(data.get('email'), success=False)
    security_manager.log_security_event('failed_login_attempt', details={
        'email': data.get('email')
    })

    return jsonify({'message': 'Invalid credentials'}), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token with security validation"""
    current_user_id = get_jwt_identity()
    jwt_claims = get_jwt()

    user = User.query.get(current_user_id)

    if not user:
        security_manager.log_security_event('refresh_user_not_found', current_user_id)
        return jsonify({'message': 'User not found'}), 404

    # Validate session security for refresh token
    is_valid, error_message = security_manager.validate_session_security(
        current_user_id,
        jwt_claims,
        session_timeout=604800  # 7 days for refresh token
    )

    if not is_valid:
        security_manager.log_security_event('refresh_token_security_failed', current_user_id, {
            'error': error_message
        })
        return jsonify({'message': error_message}), 401

    # Create new secure access token
    new_access_token = create_secure_access_token(current_user_id)

    security_manager.log_security_event('token_refreshed', current_user_id)

    return jsonify({
        'access_token': new_access_token
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Logout endpoint that revokes the current token"""
    try:
        # Revoke the current access token
        revoke_current_token()

        security_manager.log_security_event('user_logout', current_user.id, {
            'ip_address': request.remote_addr
        })

        return jsonify({'message': 'Logged out successfully'}), 200

    except Exception as e:
        security_manager.log_security_event('logout_error', current_user.id, {
            'error': str(e)
        })
        return jsonify({'message': 'Logout completed with warnings'}), 200


@auth_bp.route('/logout-all', methods=['POST'])
@token_required
def logout_all(current_user):
    """Logout from all devices by revoking all tokens for the user"""
    try:
        # Revoke all tokens for this user
        revoke_all_tokens_for_user(current_user.id)

        security_manager.log_security_event('user_logout_all_devices', current_user.id, {
            'ip_address': request.remote_addr
        })

        return jsonify({'message': 'Logged out from all devices successfully'}), 200

    except Exception as e:
        security_manager.log_security_event('logout_all_error', current_user.id, {
            'error': str(e)
        })
        return jsonify({'message': 'Logout completed with warnings'}), 200

@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Get current user profile - protected endpoint"""
    return jsonify({
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'fullname': current_user.fullname,
            'role': current_user.role
        }
    }), 200