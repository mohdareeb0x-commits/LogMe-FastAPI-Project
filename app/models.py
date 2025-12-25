"""SQLAlchemy ORM models for the authentication system.

Defines `User`, `Role`, `UserRole` (association table) and
`RefreshToken` used to persist authentication data.
"""

from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from app.db import Base
from datetime import datetime


class User(Base):
    """Represents an application user.

    Stores username, hashed password, and relationships to roles
    and refresh tokens.
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(1024), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow())

    roles = relationship("UserRole", back_populates="user")
    refresh_token = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class Role(Base):
    """A role that can be assigned to users (e.g. admin, user)."""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)

    users = relationship("UserRole", back_populates="role")


class UserRole(Base):
    """Association table between `User` and `Role`."""
    __tablename__ = "user_roles"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="users")


class RefreshToken(Base):
    """Stores hashed refresh tokens and their metadata."""
    __tablename__ = "refresh_token"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token_hash = Column(String(255), index=True)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default = False)
    created_at = Column(DateTime, default=datetime.utcnow())

    user = relationship("User", back_populates="refresh_token")