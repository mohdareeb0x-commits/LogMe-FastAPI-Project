"""Web application routes and HTML rendering.

This module defines the FastAPI application, route handlers for
authentication pages (signup / login), token handling, and a couple
of simple dashboard views. Handlers are intentionally small and
delegate persistence to SQLAlchemy sessions obtained from
`app.deps.get_db`.
"""

from fastapi import (FastAPI, HTTPException, Depends, Request, Form, status)
from fastapi.security import (OAuth2PasswordBearer, OAuth2PasswordRequestForm)
from fastapi.responses import (HTMLResponse, RedirectResponse, JSONResponse)
from jose import jwt, JWTError
from app.shemas import UserCreate
from starlette.status import HTTP_303_SEE_OTHER
from app.db import engine
from datetime import datetime, timedelta
from app.deps import get_db
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates
from app.models import (Base, User, Role, UserRole, RefreshToken)
from app.init_db import create_default_roles
from app.auth import (
    hash_password, verify_password, 
    create_access_token, get_current_user, 
    require_role, create_refresh_token,
    hash_token,
    REFRESH_KEY, ALGORITHM
)

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
templates = Jinja2Templates(directory="site")

Base.metadata.create_all(bind=engine)

fake_users_db = {}


@app.on_event("startup")
def startup_event():
    """Application startup hook.

    Ensures default roles (admin, user) exist in the database.
    """
    create_default_roles()



@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Render the public home page.

    The `request` object is required by Jinja templates to build
    absolute URLs and to access cookies if needed.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )


@app.get("/signup.html", response_class=HTMLResponse)
def signup_page(request: Request):
    """Render the signup page."""
    return templates.TemplateResponse(
        "signup.html",
        {"request": request}
    )


@app.post("/signup")
async def signup(request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    db: Session = Depends(get_db)
):
    # Check for existing username
    existing_user = db.query(User).filter(User.username == username).first()
    
    if existing_user:
        return templates.TemplateResponse(
            "signup.html",
            {
                "request": request,
                "error": "User already Exists"
            }
        )

    # Create the new user and store a hashed password
    new_user = User(
        username = username,
        password_hash = hash_password(password),
        is_active = True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Assign the selected role
    # Assign the selected role (falls back to raising if role missing)
    selected_role = db.query(Role).filter(Role.name == role).first()

    if not selected_role:
        raise HTTPException(status_code=500, detail="Selected role not found")
    
    db.add(UserRole(
        user_id=new_user.id, 
        role_id=selected_role.id
    ))
    db.commit()

    return RedirectResponse(url="/login.html", status_code=HTTP_303_SEE_OTHER)


@app.get("/login.html", response_class=HTMLResponse)
def signup_page(request: Request):
    """Render the login page."""
    return templates.TemplateResponse(
        "login.html",
        {"request": request}
    )


@app.post("/login")
async def login(
    request: Request, 
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db:Session = Depends(get_db)
):
    """Authenticate a user and issue access / refresh tokens.

    Stores a hashed refresh token in the database and sets both
    tokens as HTTP-only cookies on the response.
    """

    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=403,
            detail = "Invalid credentials"
        )
    
    access_token = create_access_token({"sub": str(user.id)})
    refresh_token = create_refresh_token({"sub": str(user.id)})

    refresh_token_db = RefreshToken(
        user_id = user.id, 
        token_hash = hash_token(refresh_token),
        expires_at = datetime.utcnow() + timedelta(days=7),
        revoked = False
    )
    db.add(refresh_token_db)
    db.commit()

    is_admin = any(
        role.role.name == "admin" for role in user.roles
    )

    response = RedirectResponse(
        url = "/admin.html" if is_admin else "/user.html",
        status_code=303
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token, 
        httponly=True,
        samesite="lax"
    )
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,
        samesite="lax"
    )

    return response


@app.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    """Log out a user by revoking the refresh token and clearing cookies."""

    refresh_token = request.cookies.get("refresh_token")

    if refresh_token:
        hashed_token = hash_token(refresh_token)

        token_db = (
            db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_token).first()
        )

        if token_db:
            token_db.revoked = True
            db.commit()

    response = RedirectResponse(url="/login.html", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response


@app.post("/refresh")
def refresh_token(request: Request, db: Session = Depends(get_db)):
    """Exchange a valid refresh token for a new access token.

    Validates the refresh token against the stored hash in the DB,
    revokes the old one and issues fresh access/refresh tokens.
    """

    refresh_token = request.cookies.get("refresh_token")

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    
    token_hash = hash_token(refresh_token)

    token_db = (
        db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash, 
            RefreshToken.revoked == False
        )
        .first()
    )

    if not token_db or token_db.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    user = db.query(User).filter(User.id == token_db.user_id).first()

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    token_db.revoked = True

    new_refresh_token = create_refresh_token()
    new_refresh_hash = hash_token(new_refresh_token)

    new_token_db = RefreshToken(
        user_id = user.id,
        token_hash = new_refresh_hash, 
        expires_at = datetime.utcnow() + timedelta(days = 7)
    )

    db.add(new_token_db)
    db.commit()

    new_access_token = create_access_token({"sub": user.username})

    response = JSONResponse({"access_token": new_access_token})

    response.set_cookie(
        "access_token",
        new_access_token,
        httponly=True
    )

    response.set_cookie(
        "refresh_token",
        new_refresh_token,
        httponly=True
    )

    return response

    
@app.get("/admin.html", response_class=HTMLResponse)
def admin(request: Request):
    """Render the admin landing page (static HTML)."""
    return templates.TemplateResponse(
        "admin.html",
        {"request": request}
    )

@app.get("/admin")
def admin_dashboard(request: Request, current_user: dict = Depends(require_role("admin"))):
    """Admin-only dashboard view. Requires `admin` role."""
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "username": current_user["username"]}
    )

@app.get("/user.html", response_class=HTMLResponse)
def user_dashboard(request: Request):
    """Return a simple JSON welcome message for authenticated users."""
    return templates.TemplateResponse(
        "user.html",
        {"request": request}
    )

@app.get("/user")
def user_dashboard(request: Request, current_user: dict = Depends(require_role("user"))):
    """User-only dashboard view. Requires `user` role."""
    return templates.TemplateResponse(
        "user.html",
        {"request": request, "username": current_user["username"]}
    )