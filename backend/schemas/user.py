"""
Pydantic schemas for user registration, authentication, and responses.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, examples=["analyst1"])
    email: EmailStr = Field(..., examples=["analyst@osintx.local"])


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=100, examples=["SecurePass123!"])


class UserLogin(BaseModel):
    username_or_email: str = Field(..., examples=["analyst1"])
    password: str = Field(..., examples=["SecurePass123!"])


class UserResponse(UserBase):
    id: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8, max_length=100)
