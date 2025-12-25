"""Database initialization helpers.

Provides helpers to create initial data required by the
application (for example default roles).
"""

from sqlalchemy.orm import Session
from app.db import SessionLocal
from app.models import Role


def create_default_roles():
    """Ensure basic roles exist in the database.

    Creates roles `admin` and `user` if they are not already present.
    This function opens its own session and closes it before
    returning.
    """
    db: Session = SessionLocal()
    try:
        roles = ["admin", "user"]

        for role_name in roles:
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                db.add(Role(name=role_name))
        
        db.commit()
        
    finally:
        # Ensure the session is properly closed
        db.close()