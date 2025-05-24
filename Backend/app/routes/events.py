from flask import Blueprint, request, jsonify
from app.models.event import Event
from app.models.comment import Comment
from app.extensions import db
from app.auth_utils import token_required, organizer_required
from datetime import datetime

bp = Blueprint("events", __name__)

@bp.route("/events", methods=["GET"])
def get_events():
    events = Event.query.all()
    return jsonify([{
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'location': event.location,
        'latitude': event.latitude,
        'longitude': event.longitude,
        'date': event.date.isoformat(),
        'image_url': event.image_url,
        'created_by': event.created_by,
        'created_at': event.created_at.isoformat(),
        'updated_at': event.updated_at.isoformat()
    } for event in events])

@bp.route("/events/<int:event_id>", methods=["GET"])
def get_event(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify({
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'location': event.location,
        'latitude': event.latitude,
        'longitude': event.longitude,
        'date': event.date.isoformat(),
        'image_url': event.image_url,
        'created_by': event.created_by,
        'created_at': event.created_at.isoformat(),
        'updated_at': event.updated_at.isoformat()
    })

@bp.route("/events", methods=["POST"])
@token_required
def create_event(current_user):
    data = request.get_json()
    
    if not all(key in data for key in ('title', 'location', 'date')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        event_date = datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    new_event = Event(
        title=data['title'],
        description=data.get('description'),
        location=data['location'],
        latitude=data.get('latitude'),
        longitude=data.get('longitude'),
        date=event_date,
        image_url=data.get('image_url'),
        created_by=current_user.id
    )
    
    db.session.add(new_event)
    db.session.commit()
    
    return jsonify({
        'id': new_event.id,
        'title': new_event.title,
        'description': new_event.description,
        'location': new_event.location,
        'latitude': new_event.latitude,
        'longitude': new_event.longitude,
        'date': new_event.date.isoformat(),
        'image_url': new_event.image_url,
        'created_by': new_event.created_by,
        'created_at': new_event.created_at.isoformat(),
        'updated_at': new_event.updated_at.isoformat()
    }), 201

@bp.route("/events/<int:event_id>", methods=["PUT"])
@token_required
def update_event(current_user, event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user owns the event or is admin
    if event.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to modify this event'}), 403
    
    data = request.get_json()
    
    if 'title' in data:
        event.title = data['title']
    if 'description' in data:
        event.description = data['description']
    if 'location' in data:
        event.location = data['location']
    if 'latitude' in data:
        event.latitude = data['latitude']
    if 'longitude' in data:
        event.longitude = data['longitude']
    if 'date' in data:
        try:
            event.date = datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
    if 'image_url' in data:
        event.image_url = data['image_url']
    
    db.session.commit()
    
    return jsonify({
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'location': event.location,
        'latitude': event.latitude,
        'longitude': event.longitude,
        'date': event.date.isoformat(),
        'image_url': event.image_url,
        'created_by': event.created_by,
        'created_at': event.created_at.isoformat(),
        'updated_at': event.updated_at.isoformat()
    })

@bp.route("/events/<int:event_id>", methods=["DELETE"])
@token_required
def delete_event(current_user, event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user owns the event or is admin
    if event.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to delete this event'}), 403
    
    db.session.delete(event)
    db.session.commit()
    return '', 204

# Event Comment Endpoints (B-S3-05: Implement postComment API for events)

@bp.route("/events/<int:event_id>/comments", methods=["GET"])
def get_event_comments(event_id):
    """Get all comments for a specific event"""
    event = Event.query.get_or_404(event_id)
    comments = Comment.query.filter_by(event_id=event_id).all()
    
    return jsonify([{
        'id': comment.id,
        'content': comment.content,
        'created_by': comment.created_by,
        'created_at': comment.created_at.isoformat(),
        'updated_at': comment.updated_at.isoformat(),
        'author': {
            'id': comment.user_author.id,
            'fullname': comment.user_author.fullname
        } if comment.user_author else None
    } for comment in comments])

@bp.route("/events/<int:event_id>/comments", methods=["POST"])
@token_required
def add_event_comment(current_user, event_id):
    """Add a new comment to an event"""
    event = Event.query.get_or_404(event_id)
    data = request.get_json()
    
    if not data or 'content' not in data or not data['content'].strip():
        return jsonify({'error': 'Comment content is required'}), 400

    new_comment = Comment(
        content=data['content'].strip(),
        event_id=event_id,
        created_by=current_user.id
    )
    
    db.session.add(new_comment)
    db.session.commit()
    
    return jsonify({
        'id': new_comment.id,
        'content': new_comment.content,
        'created_by': new_comment.created_by,
        'created_at': new_comment.created_at.isoformat(),
        'updated_at': new_comment.updated_at.isoformat(),
        'author': {
            'id': new_comment.user_author.id,
            'fullname': new_comment.user_author.fullname
        } if new_comment.user_author else None
    }), 201

@bp.route("/events/<int:event_id>/comments/<int:comment_id>", methods=["PUT"])
@token_required
def update_event_comment(current_user, event_id, comment_id):
    """Update a specific comment on an event"""
    comment = Comment.query.get_or_404(comment_id)
    
    # Verify the comment belongs to the specified event
    if comment.event_id != event_id:
        return jsonify({'error': 'Comment does not belong to this event'}), 404
    
    # Check if user owns the comment or is admin
    if comment.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to modify this comment'}), 403
    
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({'error': 'Comment content is required'}), 400

    comment.content = data['content']
    db.session.commit()
    
    return jsonify({
        'id': comment.id,
        'content': comment.content,
        'created_by': comment.created_by,
        'created_at': comment.created_at.isoformat(),
        'updated_at': comment.updated_at.isoformat(),
        'author': {
            'id': comment.user_author.id,
            'fullname': comment.user_author.fullname
        } if comment.user_author else None
    })

@bp.route("/events/<int:event_id>/comments/<int:comment_id>", methods=["DELETE"])
@token_required
def delete_event_comment(current_user, event_id, comment_id):
    """Delete a specific comment from an event"""
    comment = Comment.query.get_or_404(comment_id)
    
    # Verify the comment belongs to the specified event
    if comment.event_id != event_id:
        return jsonify({'error': 'Comment does not belong to this event'}), 404
    
    # Check if user owns the comment or is admin
    if comment.created_by != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized to delete this comment'}), 403
    
    db.session.delete(comment)
    db.session.commit()
    return '', 204

# Organizer-specific endpoints

@bp.route("/organizer/events", methods=["GET"])
@organizer_required
def get_organizer_events(current_user):
    """Get all events created by the current organizer"""
    events = Event.query.filter_by(created_by=current_user.id).all()
    return jsonify([{
        'id': event.id,
        'title': event.title,
        'description': event.description,
        'location': event.location,
        'latitude': event.latitude,
        'longitude': event.longitude,
        'date': event.date.isoformat(),
        'image_url': event.image_url,
        'created_by': event.created_by,
        'created_at': event.created_at.isoformat(),
        'updated_at': event.updated_at.isoformat()
    } for event in events])

@bp.route("/organizer/stats", methods=["GET"])
@organizer_required
def get_organizer_stats(current_user):
    """Get statistics for the organizer's events"""
    total_events = Event.query.filter_by(created_by=current_user.id).count()
    return jsonify({
        'total_events': total_events,
        'organizer_name': current_user.fullname
    })