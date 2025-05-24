from sqlalchemy.orm import relationship
from app.extensions import db
from .event import Event
from .user import User
from .listing import Listing
from .comment import Comment
from .user_preferences import UserBookmark, UserLike
from .user_booking import UserBooking

# set up relationship now that both are loaded
#Event.organizer = relationship("User", back_populates="events")

# Make models available at the package level
__all__ = ['User', 'Event', 'Comment', 'Listing', 'UserBookmark', 'UserLike', 'UserBooking']