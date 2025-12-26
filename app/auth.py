"""Authentication utilities and token helpers.

This module centralizes password hashing, verification, and JWT
creation/verification logic. It also exposes a small dependency
factory `require_role` for enforcing role-based access via cookies.
"""

from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, Cookie, Request
import hashlib

ACCESS_KEY = "WbqzN2T8aivotWDrIgTQr"
REFRESH_KEY = "G9ZEhEhbuklqVX1zAY7ynA="
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 15
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_token(token: str) -> str :
    """Return a SHA-256 hex digest for the given token string.

    Refresh tokens are stored in the database as their hash rather
    than the raw token for improved security.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str): # Print first 10 characters
    """Hash a plaintext password using the configured passlib context."""
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    """Verify a plaintext password against a stored hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict):
    """Create a JWT access token with a short expiration."""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, ACCESS_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create a long-lived JWT refresh token.

    Refresh tokens are intended to be stored server-side as a hash.
    """
    payload = data.copy()
    payload["type"] = "refresh"
    payload["exp"] = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode(payload, REFRESH_KEY, algorithm=ALGORITHM)


def get_current_user(request: Request,access_token: str = None):
    """Decode a JWT access token and return a minimal user dict.

    Raises `HTTPException(401)` when the token is missing or invalid.
    """
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = jwt.decode(access_token, ACCESS_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise ValueError("Invalid token")
        return {"username": username, "role": role}
    
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")    


def get_user(request: Request):
    """Decode a JWT access token and return a minimal user dict.
    Raises `HTTPException(401)` when the token is missing or invalid.
    """
    access_token = request.cookies.get("access_token")

    if not access_token:
        raise HTTPException(status_code=401, detail="Not Signed In")
    
    payload = jwt.decode(access_token, ACCESS_KEY, algorithms=[ALGORITHM])

    return {
        "id" : payload.get("sub"),
        "role": payload.get("role")
    }
    

def require_role(required_role):
    """Return a FastAPI dependency that enforces role membership.

    `required_role` may be a single string (e.g. "admin") or a list
    of allowed roles. The returned callable reads the access token
    from a cookie and validates the contained role.
    """
    
    def role_checker(access_token: str = Cookie(None)):
        """Dependency function used by FastAPI endpoints."""
        if not access_token:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        current_user = get_current_user(access_token)
        
        # Handle both single string and list of roles
        allowed_roles = required_role if isinstance(required_role, list) else [required_role]
        
        if current_user.get("role") not in allowed_roles:
            raise HTTPException(status_code=403, detail="Access Forbidden")
        return current_user
    
    return role_checker


def admin_only(user = Depends(get_user)):
    """To check if the logged in user has admin role or not 
    and return outcome."""

    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admins Only")
    return user

