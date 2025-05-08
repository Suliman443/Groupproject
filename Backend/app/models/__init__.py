from sqlalchemy.orm import relationship
from .event import Event
from .user import User

# set up relationship now that both are loaded
#Event.organizer = relationship("User", back_populates="events")