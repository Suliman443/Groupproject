from app.extensions import db
from datetime import datetime

class UserBookmark(db.Model):
    __tablename__ = "user_bookmarks"

    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate bookmarks
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_user_event_bookmark'),)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('bookmarks', lazy=True, cascade='all, delete-orphan'))
    event = db.relationship('Event', backref=db.backref('bookmarked_by', lazy=True, cascade='all, delete-orphan'))

class UserLike(db.Model):
    __tablename__ = "user_likes"

    id = db.Column(db.Integer, primary_key=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent duplicate likes
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_user_event_like'),)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('likes', lazy=True, cascade='all, delete-orphan'))
    event = db.relationship('Event', backref=db.backref('liked_by', lazy=True, cascade='all, delete-orphan')) 