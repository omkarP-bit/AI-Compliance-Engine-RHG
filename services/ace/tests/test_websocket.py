from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ace.api.websocket import ConnectionManager, publish_event
from ace.main import app


class TestConnectionManager:
    def setup_method(self):
        self.cm = ConnectionManager()

    @pytest.mark.asyncio
    async def test_connect_adds_to_active(self):
        ws = MagicMock()
        ws.accept = AsyncMock()
        await self.cm.connect(ws)
        assert ws in self.cm.active
        ws.accept.assert_awaited_once()

    def test_disconnect_removes_from_active(self):
        ws = MagicMock()
        self.cm.active.append(ws)
        self.cm.disconnect(ws)
        assert ws not in self.cm.active

    @pytest.mark.asyncio
    async def test_broadcast_sends_to_all(self):
        ws1 = MagicMock()
        ws1.send_json = AsyncMock()
        ws2 = MagicMock()
        ws2.send_json = AsyncMock()
        self.cm.active.extend([ws1, ws2])

        await self.cm.broadcast({"event": "test"})
        ws1.send_json.assert_awaited_once_with({"event": "test"})
        ws2.send_json.assert_awaited_once_with({"event": "test"})

    @pytest.mark.asyncio
    async def test_broadcast_removes_dead_connections(self):
        ws_alive = MagicMock()
        ws_alive.send_json = AsyncMock()
        ws_dead = MagicMock()
        ws_dead.send_json = AsyncMock(side_effect=Exception("gone"))
        self.cm.active.extend([ws_alive, ws_dead])

        await self.cm.broadcast({"event": "test"})
        assert ws_dead not in self.cm.active
        assert ws_alive in self.cm.active


class TestPublishEvent:
    @pytest.mark.asyncio
    async def test_publishes_to_redis(self):
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()

        with patch("ace.api.websocket.aioredis.from_url", return_value=mock_redis):
            await publish_event("scan.completed", {"scan_id": "abc"})
            mock_redis.publish.assert_awaited_once()
            args, _ = mock_redis.publish.await_args
            assert args[0] == "ace:events"
            assert "scan.completed" in args[1]

    @pytest.mark.asyncio
    async def test_closes_redis_connection(self):
        mock_redis = AsyncMock()
        mock_redis.publish = AsyncMock()
        mock_redis.aclose = AsyncMock()

        with patch("ace.api.websocket.aioredis.from_url", return_value=mock_redis):
            await publish_event("gate.decision", {"decision": "BLOCK"})
            mock_redis.aclose.assert_awaited_once()


class TestWebSocketEndpoint:
    def test_websocket_accepts_connection(self):
        with patch("ace.api.websocket.aioredis.from_url") as mock_redis_factory:
            mock_redis = AsyncMock()
            mock_pubsub = AsyncMock()
            mock_pubsub.subscribe = AsyncMock()
            mock_pubsub.unsubscribe = AsyncMock()
            mock_pubsub.aclose = AsyncMock()

            async def listen_gen():
                yield {"type": "message", "data": '{"event": "test"}'}
                yield {"type": "message", "data": '{"event": "done"}'}

            mock_pubsub.listen = AsyncMock(return_value=listen_gen())
            mock_redis.pubsub = AsyncMock(return_value=mock_pubsub)
            mock_redis.aclose = AsyncMock()
            mock_redis_factory.return_value = mock_redis

            client = TestClient(app)
            with client.websocket_connect("/ws/events") as ws:
                data = ws.receive_json()
                assert data["event"] == "test"
                data = ws.receive_json()
                assert data["event"] == "done"
