from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class EventBase(BaseModel):
    title: str
    description: Optional[str] = None
    location: str
    date: datetime
    time: str

class EventCreate(EventBase):
    organizer_id: int

class EventOut(EventBase):
    id: int
    organizer_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True