"""Dependency utilities for FastAPI routes.

This module contains helper dependencies that endpoints can declare
with `Depends()`. Currently it exposes `get_db()` which yields a
SQLAlchemy session and ensures it is closed after use.
"""

from app.db import SessionLocal


def get_db():
    """Yield a SQLAlchemy session and close it when the request ends.

    Usage: `db: Session = Depends(get_db)` in route handlers.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()