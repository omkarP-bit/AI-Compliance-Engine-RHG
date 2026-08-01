import logging
import os

from fastapi import FastAPI

logger = logging.getLogger(__name__)

from ace.api.routes import router
from ace.api.websocket import ws_router

app = FastAPI(title="ACE — AI Compliance Engine", version="0.1.0")
app.include_router(router)
app.include_router(ws_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ace"}


@app.on_event("startup")
async def startup():
    if os.environ.get("ACE_METRICS_ENABLED", "true").lower() == "true":
        try:
            from ace.metrics.prometheus import start_metrics_server

            port = int(os.environ.get("ACE_METRICS_PORT", "9090"))
            start_metrics_server(port)
        except RuntimeError:
            pass
