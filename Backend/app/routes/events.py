from flask import Blueprint, request, jsonify
from app.models.event import Event
from app.extensions import db
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
def create_event():
    data = request.get_json()
    
    if not all(key in data for key in ('title', 'location', 'date', 'created_by')):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        event_date = datetime.fromisoformat(data['date'].replace('Z', '+00:00'))
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    new_event = Event(
        title=data['title'],
        description=data.get('description'),
        location=data['location'],
        date=event_date,
        image_url=data.get('image_url'),
        created_by=data['created_by']
    )
    
    db.session.add(new_event)
    db.session.commit()
    
    return jsonify({
        'id': new_event.id,
        'title': new_event.title,
        'description': new_event.description,
        'location': new_event.location,
        'date': new_event.date.isoformat(),
        'image_url': new_event.image_url,
        'created_by': new_event.created_by,
        'created_at': new_event.created_at.isoformat(),
        'updated_at': new_event.updated_at.isoformat()
    }), 201

@bp.route("/events/<int:event_id>", methods=["PUT"])
def update_event(event_id):
    event = Event.query.get_or_404(event_id)
    data = request.get_json()
    
    if 'title' in data:
        event.title = data['title']
    if 'description' in data:
        event.description = data['description']
    if 'location' in data:
        event.location = data['location']
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
        'date': event.date.isoformat(),
        'image_url': event.image_url,
        'created_by': event.created_by,
        'created_at': event.created_at.isoformat(),
        'updated_at': event.updated_at.isoformat()
    })

@bp.route("/events/<int:event_id>", methods=["DELETE"])
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    return '', 204