import asyncio
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .config import settings
from .routers import api, ws_agent, ws_browser, ws_phone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")


@asynccontextmanager
async def lifespan(app):
    from .vault import vault_manager
    async def _vault_expiry_loop():
        while True:
            await asyncio.sleep(30)
            vault_manager.expire_stale()
    task = asyncio.create_task(_vault_expiry_loop())
    yield
    task.cancel()

app = FastAPI(title="Automaite Terminal Relay", lifespan=lifespan)

# CORS: restrict cross-origin access if configured
if settings.cors_origins:
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

from fastapi.responses import FileResponse

app.include_router(api.router)
app.include_router(ws_agent.router)
app.include_router(ws_browser.router)
app.include_router(ws_phone.router)


@app.get("/connect")
async def connect_page():
    return FileResponse("static/connect.html", media_type="text/html")


@app.get("/app-login")
async def app_login_page():
    return FileResponse("static/app-login.html", media_type="text/html")

app.mount("/", StaticFiles(directory="static", html=True), name="static")
