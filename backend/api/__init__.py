from fastapi import FastAPI
from . import ip, phone

def create_app() -> FastAPI:
    app = FastAPI(title="OSINT-X API")
    app.include_router(ip.router)
    app.include_router(phone.router)
    return app
