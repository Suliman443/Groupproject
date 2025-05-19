from app import create_app
from app.models import User, Event
from app.extensions import db
from datetime import datetime, timedelta

def init_db():
    app = create_app()
    with app.app_context():
        # Create tables
        db.create_all()
        
        # Create a test user if it doesn't exist
        test_user = User.query.filter_by(email='test@example.com').first()
        if not test_user:
            test_user = User(
                email='test@example.com',
                hashed_password='pbkdf2:sha256:600000$test123$test456',  # This is just for testing
                role='user'
            )
            db.session.add(test_user)
            db.session.commit()
        
        # Create sample events
        sample_events = [
            {
                'title': 'Summer Music Festival',
                'description': 'Join us for a day of amazing music and entertainment!',
                'location': 'Central Park',
                'latitude': 40.7829,
                'longitude': -73.9654,
                'date': datetime.now() + timedelta(days=7),
                'image_url': 'https://images.unsplash.com/photo-1470229722913-7c0e2dbbafd3',
                'created_by': test_user.id
            },
            {
                'title': 'Food & Wine Expo',
                'description': 'Experience the finest cuisines and wines from around the world.',
                'location': 'Convention Center',
                'latitude': 40.7589,
                'longitude': -73.9851,
                'date': datetime.now() + timedelta(days=14),
                'image_url': 'https://images.unsplash.com/photo-1414235077428-338989a2e8c0',
                'created_by': test_user.id
            },
            {
                'title': 'Tech Conference 2024',
                'description': 'Learn about the latest trends in technology and innovation.',
                'location': 'Tech Hub',
                'latitude': 40.7128,
                'longitude': -74.0060,
                'date': datetime.now() + timedelta(days=21),
                'image_url': 'https://images.unsplash.com/photo-1505373877841-8d25f7d46678',
                'created_by': test_user.id
            }
        ]
        
        # Add events to database
        for event_data in sample_events:
            existing_event = Event.query.filter_by(title=event_data['title']).first()
            if not existing_event:
                event = Event(**event_data)
                db.session.add(event)
        
        db.session.commit()
        print("Database initialized with sample data!")

if __name__ == '__main__':
    init_db() 