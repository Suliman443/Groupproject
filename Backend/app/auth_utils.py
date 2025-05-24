from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from app.models.user import User


def token_required(f):
    """
    Decorator to require valid JWT token for accessing routes
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                return jsonify({'message': 'Invalid token - user not found'}), 401
                
            return f(current_user=current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired'}), 401
    
    return decorated


def admin_required(f):
    """
    Decorator to require admin role for accessing routes
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                return jsonify({'message': 'Invalid token - user not found'}), 401
                
            if current_user.role != 'admin':
                return jsonify({'message': 'Admin access required'}), 403
                
            return f(current_user=current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired'}), 401
    
    return decorated


def get_current_user():
    """
    Get current authenticated user from JWT token
    """
    try:
        current_user_id = get_jwt_identity()
        return User.query.get(current_user_id)
    except:
        return None


def organizer_required(f):
    """
    Decorator to require organizer role for accessing routes
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            current_user = User.query.get(current_user_id)
            
            if not current_user:
                return jsonify({'message': 'Invalid token - user not found'}), 401
                
            if current_user.role != 'organizer':
                return jsonify({'message': 'Organizer access required'}), 403
                
            return f(current_user=current_user, *args, **kwargs)
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired'}), 401
    
    return decorated 