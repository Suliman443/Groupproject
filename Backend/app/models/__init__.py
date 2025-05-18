from sqlalchemy.orm import relationship
from app.extensions import db
from .event import Event
from .user import User

# set up relationship now that both are loaded
#Event.organizer = relationship("User", back_populates="events")

# Define Comment model here since it's referenced by User and Event
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)

# Make models available at the package level
__all__ = ['User', 'Event', 'Comment']