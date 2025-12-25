"""Pydantic schemas for request/response validation.

Minimal models are provided for the signup/login workflows.
"""

from pydantic import BaseModel


class Base(BaseModel):
    """Base schema containing common fields for user operations."""
    username: str
    password: str
    role : str


class UserCreate(Base):
    """Schema used when creating a new user via the signup form."""
    pass