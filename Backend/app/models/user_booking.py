from app.extensions import db
from datetime import datetime

class UserBooking(db.Model):
    __tablename__ = "user_bookings"

    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    booking_date = db.Column(db.Date, nullable=False)
    booking_time = db.Column(db.String(10), nullable=False)  # Format: "HH:MM"
    quantity = db.Column(db.Integer, nullable=False, default=1)
    status = db.Column(db.String(20), nullable=False, default='confirmed')  # confirmed, cancelled, pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('bookings', lazy=True, cascade='all, delete-orphan'))
    event = db.relationship('Event', backref=db.backref('user_bookings', lazy=True, cascade='all, delete-orphan'))
    
    def __repr__(self):
        return f'<UserBooking {self.id}: User {self.user_id}, Event {self.event_id}, Date {self.booking_date}>' 