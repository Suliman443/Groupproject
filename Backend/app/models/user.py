from app.extensions import db

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    fullname = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), default='user')
    
    # Relationships
    created_events = db.relationship('Event', backref='creator', lazy=True)
    created_listings = db.relationship('Listing', backref='creator', lazy=True)
    user_comments = db.relationship('Comment', backref='user_author', lazy=True)