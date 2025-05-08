from app.models.event import Event
from app.schemas.event import EventCreate
from datetime import datetime
from datetime import time

def test_sqlalchemy_model():
    e = Event(
        title="Test Event",
        description="Example description",
        location="Riyadh",
        date=datetime.fromisoformat("2025-05-10T18:00:00"),
        time=time(18.0),
        organizer_id=1
    )
    print("✅ SQLAlchemy Event model created successfully:")
    print(e)

def test_pydantic_schema():
    payload = {
        "title": "Test Event",
        "description": "Example",
        "location": "Riyadh",
        "date": "2025-05-10T18:00:00",
        "time": "18:00",
        "organizer_id": 1
    }
    event_data = EventCreate(**payload)
    print("✅ Pydantic EventCreate schema validated successfully:")
    print(event_data)

if __name__ == "__main__":
    #test_sqlalchemy_model()
    print("-" * 40)
    test_pydantic_schema()