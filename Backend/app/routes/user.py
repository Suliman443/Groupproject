from flask import Blueprint, request, jsonify
from app.models import User, Event, UserBookmark, UserLike, UserBooking
from app.extensions import db
from app.auth_utils import token_required
from datetime import datetime

user_bp = Blueprint('user', __name__)

# Bookmark endpoints
@user_bp.route('/bookmarks', methods=['GET'])
@token_required
def get_user_bookmarks(current_user):
    """Get all bookmarks for the current user"""
    try:
        bookmarks = db.session.query(UserBookmark, Event).join(
            Event, UserBookmark.event_id == Event.id
        ).filter(UserBookmark.user_id == current_user.id).all()
        
        result = []
        for bookmark, event in bookmarks:
            result.append({
                'id': bookmark.id,
                'event_id': event.id,
                'event': {
                    'id': event.id,
                    'title': event.title,
                    'description': event.description,
                    'date': event.date.isoformat() if event.date else None,
                    'location': event.location,
                    'image_url': event.image_url
                },
                'created_at': bookmark.created_at.isoformat()
            })
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/bookmarks', methods=['POST'])
@token_required
def add_bookmark(current_user):
    """Add a bookmark for the current user"""
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        
        if not event_id:
            return jsonify({'error': 'event_id is required'}), 400
        
        # Check if event exists
        event = Event.query.get(event_id)
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        # Check if already bookmarked
        existing_bookmark = UserBookmark.query.filter_by(
            user_id=current_user.id, 
            event_id=event_id
        ).first()
        
        if existing_bookmark:
            return jsonify({'error': 'Event already bookmarked'}), 400
        
        # Create new bookmark
        bookmark = UserBookmark(
            user_id=current_user.id,
            event_id=event_id
        )
        
        db.session.add(bookmark)
        db.session.commit()
        
        return jsonify({
            'message': 'Event bookmarked successfully',
            'bookmark': {
                'id': bookmark.id,
                'event_id': event_id,
                'created_at': bookmark.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/bookmarks/<int:event_id>', methods=['DELETE'])
@token_required
def remove_bookmark(current_user, event_id):
    """Remove a bookmark for the current user"""
    try:
        bookmark = UserBookmark.query.filter_by(
            user_id=current_user.id,
            event_id=event_id
        ).first()
        
        if not bookmark:
            return jsonify({'error': 'Bookmark not found'}), 404
        
        db.session.delete(bookmark)
        db.session.commit()
        
        return jsonify({'message': 'Bookmark removed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Like endpoints
@user_bp.route('/likes', methods=['GET'])
@token_required
def get_user_likes(current_user):
    """Get all likes for the current user"""
    try:
        likes = db.session.query(UserLike, Event).join(
            Event, UserLike.event_id == Event.id
        ).filter(UserLike.user_id == current_user.id).all()
        
        result = []
        for like, event in likes:
            result.append({
                'id': like.id,
                'event_id': event.id,
                'event': {
                    'id': event.id,
                    'title': event.title,
                    'description': event.description,
                    'date': event.date.isoformat() if event.date else None,
                    'location': event.location,
                    'image_url': event.image_url
                },
                'created_at': like.created_at.isoformat()
            })
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/likes', methods=['POST'])
@token_required
def add_like(current_user):
    """Add a like for the current user"""
    try:
        data = request.get_json()
        event_id = data.get('event_id')
        
        if not event_id:
            return jsonify({'error': 'event_id is required'}), 400
        
        # Check if event exists
        event = Event.query.get(event_id)
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        # Check if already liked
        existing_like = UserLike.query.filter_by(
            user_id=current_user.id, 
            event_id=event_id
        ).first()
        
        if existing_like:
            return jsonify({'error': 'Event already liked'}), 400
        
        # Create new like
        like = UserLike(
            user_id=current_user.id,
            event_id=event_id
        )
        
        db.session.add(like)
        db.session.commit()
        
        return jsonify({
            'message': 'Event liked successfully',
            'like': {
                'id': like.id,
                'event_id': event_id,
                'created_at': like.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/likes/<int:event_id>', methods=['DELETE'])
@token_required
def remove_like(current_user, event_id):
    """Remove a like for the current user"""
    try:
        like = UserLike.query.filter_by(
            user_id=current_user.id,
            event_id=event_id
        ).first()
        
        if not like:
            return jsonify({'error': 'Like not found'}), 404
        
        db.session.delete(like)
        db.session.commit()
        
        return jsonify({'message': 'Like removed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Booking endpoints
@user_bp.route('/bookings', methods=['GET'])
@token_required
def get_user_bookings(current_user):
    """Get all bookings for the current user"""
    try:
        bookings = db.session.query(UserBooking, Event).join(
            Event, UserBooking.event_id == Event.id
        ).filter(UserBooking.user_id == current_user.id).all()
        
        result = []
        for booking, event in bookings:
            result.append({
                'id': booking.id,
                'event_id': event.id,
                'event': {
                    'id': event.id,
                    'title': event.title,
                    'description': event.description,
                    'date': event.date.isoformat() if event.date else None,
                    'location': event.location,
                    'image_url': event.image_url
                },
                'booking_date': booking.booking_date.isoformat() if booking.booking_date else None,
                'booking_time': booking.booking_time,
                'quantity': booking.quantity,
                'status': booking.status,
                'created_at': booking.created_at.isoformat()
            })
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@user_bp.route('/bookings', methods=['POST'])
@token_required
def create_booking(current_user):
    """Create a new booking for the current user"""
    try:
        data = request.get_json()
        
        required_fields = ['event_id', 'booking_date', 'booking_time', 'quantity']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Check if event exists
        event = Event.query.get(data['event_id'])
        if not event:
            return jsonify({'error': 'Event not found'}), 404
        
        # Parse booking date
        try:
            booking_date = datetime.strptime(data['booking_date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        
        # Create new booking
        booking = UserBooking(
            user_id=current_user.id,
            event_id=data['event_id'],
            booking_date=booking_date,
            booking_time=data['booking_time'],
            quantity=int(data['quantity']),
            status='confirmed'
        )
        
        db.session.add(booking)
        db.session.commit()
        
        return jsonify({
            'message': 'Booking created successfully',
            'booking': {
                'id': booking.id,
                'event_id': booking.event_id,
                'booking_date': booking.booking_date.isoformat(),
                'booking_time': booking.booking_time,
                'quantity': booking.quantity,
                'status': booking.status,
                'created_at': booking.created_at.isoformat()
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/bookings/<int:booking_id>', methods=['PUT'])
@token_required
def update_booking(current_user, booking_id):
    """Update a booking for the current user"""
    try:
        booking = UserBooking.query.filter_by(
            id=booking_id,
            user_id=current_user.id
        ).first()
        
        if not booking:
            return jsonify({'error': 'Booking not found'}), 404
        
        data = request.get_json()
        
        # Update fields if provided
        if 'booking_date' in data:
            try:
                booking.booking_date = datetime.strptime(data['booking_date'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        
        if 'booking_time' in data:
            booking.booking_time = data['booking_time']
        
        if 'quantity' in data:
            booking.quantity = int(data['quantity'])
        
        if 'status' in data:
            booking.status = data['status']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Booking updated successfully',
            'booking': {
                'id': booking.id,
                'event_id': booking.event_id,
                'booking_date': booking.booking_date.isoformat(),
                'booking_time': booking.booking_time,
                'quantity': booking.quantity,
                'status': booking.status,
                'created_at': booking.created_at.isoformat()
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@user_bp.route('/bookings/<int:booking_id>', methods=['DELETE'])
@token_required
def delete_booking(current_user, booking_id):
    """Delete a booking for the current user"""
    try:
        booking = UserBooking.query.filter_by(
            id=booking_id,
            user_id=current_user.id
        ).first()
        
        if not booking:
            return jsonify({'error': 'Booking not found'}), 404
        
        db.session.delete(booking)
        db.session.commit()
        
        return jsonify({'message': 'Booking deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 