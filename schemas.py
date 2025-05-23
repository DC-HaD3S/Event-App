from pydantic import BaseModel
from datetime import datetime
from enum import Enum
from typing import Optional, List

class Role(str, Enum):
    OWNER = "Owner"
    EDITOR = "Editor"
    VIEWER = "Viewer"

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: Role

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: Role

class Token(BaseModel):
    access_token: str
    token_type: str

class EventCreate(BaseModel):
    title: str
    description: str
    start_time: datetime
    end_time: datetime
    location: Optional[str] = None
    is_recurring: bool = False
    recurrence_pattern: Optional[str] = None

class EventOut(BaseModel):
    id: int
    title: str
    description: str
    start_time: datetime
    end_time: datetime
    location: Optional[str]
    is_recurring: bool
    recurrence_pattern: Optional[str]
    owner_id: int

class PermissionCreate(BaseModel):
    user_id: int
    role: Role

class PermissionOut(BaseModel):
    user_id: int
    role: Role

class EventHistoryOut(BaseModel):
    version: int
    title: str
    description: str
    start_time: datetime
    end_time: datetime
    location: Optional[str]
    modified_by: int
    modified_at: datetime