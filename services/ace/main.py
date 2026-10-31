import asyncio
import logging
import os

from fastapi import FastAPI

from ace.api.agent_routes import router as agent_router
from ace.api.compatibility import compat_router
from ace.api.routes import opa, router
from ace.api.websocket import ws_router

logger = logging.getLogger(__name__)

#: How often ACE probes OPA and refreshes ``ace_opa_health``.
OPA_HEALTH_INTERVAL_SECONDS = float(os.environ.get("OPA_HEALTH_INTERVAL_SECONDS", "15"))

_opa_health_task: asyncio.Task | None = None


async def _poll_opa_health() -> None:
    """Keep the ``ace_opa_health`` gauge in step with the real OPA state.

    A label-less Prometheus gauge exports its default ``0`` immediately, so
    without this loop the dashboard reads DOWN even while OPA is healthy.
    """
    from ace.metrics.prometheus import track_opa_health

    while True:
        try:
            track_opa_health(await opa.health())
        except Exception:  # noqa: BLE001 - a failed probe means "down"
            track_opa_health(False)
        await asyncio.sleep(OPA_HEALTH_INTERVAL_SECONDS)


app = FastAPI(title="ACE — AI Compliance Engine", version="2.0.0")
app.include_router(router)
app.include_router(agent_router)
app.include_router(compat_router)
app.include_router(ws_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "ace"}


@app.on_event("startup")
async def startup():
    global _opa_health_task
    if os.environ.get("ACE_METRICS_ENABLED", "true").lower() == "true":
        try:
            from ace.metrics.prometheus import start_metrics_server

            port = int(os.environ.get("ACE_METRICS_PORT", "9090"))
            start_metrics_server(port)
        except RuntimeError:
            pass
    if _opa_health_task is None:
        _opa_health_task = asyncio.create_task(_poll_opa_health())


@app.on_event("shutdown")
async def shutdown():
    global _opa_health_task
    if _opa_health_task is not None:
        _opa_health_task.cancel()
        try:
            await _opa_health_task
        except asyncio.CancelledError:
            pass
        _opa_health_task = None
