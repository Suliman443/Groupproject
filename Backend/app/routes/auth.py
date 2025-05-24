from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from app.models import User  # Import from models package
from app.extensions import db
from app.auth_utils import token_required

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    # Validate required fields
    if not all(k in data for k in ['email', 'password', 'fullname']):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400
        
    # Determine role (default to 'user', but allow 'organizer' if specified)
    role = data.get('role', 'user')
    if role not in ['user', 'organizer']:
        role = 'user'
        
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        email=data['email'],
        hashed_password=hashed_password,
        fullname=data['fullname'],
        role=role
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
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
        return jsonify({'message': 'Error creating user'}), 500

@auth_bp.route('/organizer/signup', methods=['POST'])
def organizer_signup():
    """Dedicated endpoint for organizer registration"""
    data = request.get_json()
    
    # Validate required fields
    if not all(k in data for k in ['email', 'password', 'fullname']):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter_by(email=data['email']).first()
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 400
        
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_organizer = User(
        email=data['email'],
        hashed_password=hashed_password,
        fullname=data['fullname'],
        role='organizer'
    )
    
    try:
        db.session.add(new_organizer)
        db.session.commit()
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
        return jsonify({'message': 'Error creating organizer account'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not all(k in data for k in ['email', 'password']):
        return jsonify({'message': 'Missing email or password'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if user and check_password_hash(user.hashed_password, data['password']):
        # Create JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
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
    
    return jsonify({'message': 'Invalid credentials'}), 401

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({
        'access_token': new_access_token
    }), 200

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