from app.extensions import db
from datetime import datetime

class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True, index=True)
    content = db.Column(db.Text, nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'))
    listing_id = db.Column(db.Integer, db.ForeignKey('listings.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    # (No author relationship here)

    __table_args__ = (
        db.CheckConstraint('(event_id IS NOT NULL AND listing_id IS NULL) OR (event_id IS NULL AND listing_id IS NOT NULL)',
                          name='check_comment_reference'),
    ) 