import json
import logging
import os

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

ws_router = APIRouter()
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, message: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except (ConnectionError, OSError):
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()


@ws_router.websocket("/ws/events")
async def events(websocket: WebSocket):
    await manager.connect(websocket)
    redis = aioredis.from_url(REDIS_URL)
    pubsub = await redis.pubsub()
    await pubsub.subscribe("ace:events")

    try:
        async for message in await pubsub.listen():
            if message["type"] == "message":
                data = json.loads(message["data"])
                await websocket.send_json(data)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    finally:
        await pubsub.unsubscribe("ace:events")
        await redis.aclose()


async def publish_event(event_type: str, payload: dict):
    try:
        redis = aioredis.from_url(REDIS_URL)
        event = {"event_type": event_type, **payload}
        await redis.publish("ace:events", json.dumps(event))
        await redis.aclose()
    except aioredis.RedisError:
        pass
