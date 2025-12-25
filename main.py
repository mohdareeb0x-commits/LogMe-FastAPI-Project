"""Entrypoint for running the FastAPI application.

This module starts a Uvicorn server that loads the FastAPI
application instance located at `app.app:app`.
"""
import uvicorn


# Run the application
if __name__ == "__main__":
    uvicorn.run("app.app:app", host="127.0.0.1", port=8000, reload=True)
