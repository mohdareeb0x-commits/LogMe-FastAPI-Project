# LogMe — FastAPI Authentication Demo

A minimal FastAPI project demonstrating user signup/login with role-based access control (RBAC), JWT access/refresh tokens, and simple HTML pages rendered with Jinja2.

This repository is intended as a learning/demo project — do not use the default secret keys or configuration in production.

## Features
- User signup and login with password hashing (bcrypt via passlib)
- JWT access and refresh tokens stored in HTTP-only cookies
- Role-based access (`admin` / `user`) and protected routes
- Simple SQLite persistence (`base.db`) via SQLAlchemy ORM
- Jinja2 templates in the `site/` folder (Bootstrap-based)

## Quickstart

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install fastapi uvicorn sqlalchemy passlib[bcrypt] python-jose[cryptography] jinja2
```

2. Start the app (development):

```bash
python main.py
# or
uvicorn "app.app:app" --reload
```

3. Open http://127.0.0.1:8000 in your browser.

## Important files
- `main.py` — simple entrypoint that runs Uvicorn.
- `app/app.py` — FastAPI application and route handlers.
- `app/auth.py` — password / token helpers and RBAC dependency.
- `app/models.py` — SQLAlchemy ORM models (User, Role, UserRole, RefreshToken).
- `app/db.py` — DB engine and session factory.
- `app/deps.py` — FastAPI dependency helpers (e.g. `get_db`).
- `site/` — Jinja2 HTML templates (index, login, signup, admin, user/blog).

## Database
- Uses SQLite at `base.db` by default. Tables are created automatically at startup via SQLAlchemy `Base.metadata.create_all(bind=engine)`.

## Security notes
- The signing keys (`ACCESS_KEY`, `REFRESH_KEY`) and token parameters are hard-coded in `app/auth.py` for demo purposes. Replace them with secure values and load from environment variables in real deployments.
- Consider using HTTPS and secure cookie settings for production.

## Git
- A `.gitignore` has been added to exclude virtualenvs, local databases and editor files.

