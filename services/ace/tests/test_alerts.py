import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from ace.alerts.router import AlertRouter, AlertPayload, AlertSeverity
from ace.alerts.channels.slack import SlackChannel
from ace.alerts.channels.sqs import SQSChannel


SAMPLE_PAYLOAD = AlertPayload(
    event_type="gate.decision",
    pipeline_id="pipe-123",
    repo="org/service",
    environment="production",
    severity=AlertSeverity.HIGH,
    findings_count=3,
    blocking_rules=["CIS-K8S-5.2.1", "CIS-K8S-5.2.2"],
    decision="BLOCK",
    report_url="http://dashboard/report/123",
)


@pytest.mark.asyncio
class TestAlertRouter:
    async def test_dispatches_to_all_channels(self):
        ch1 = AsyncMock()
        ch1.send = AsyncMock(return_value=True)
        ch2 = AsyncMock()
        ch2.send = AsyncMock(return_value=True)

        router = AlertRouter()
        router.register(ch1).register(ch2)
        await router.dispatch(SAMPLE_PAYLOAD)

        ch1.send.assert_called_once_with(SAMPLE_PAYLOAD)
        ch2.send.assert_called_once_with(SAMPLE_PAYLOAD)

    async def test_continues_if_one_channel_fails(self):
        failing = AsyncMock()
        failing.send = AsyncMock(side_effect=Exception("Slack is down"))
        working = AsyncMock()
        working.send = AsyncMock(return_value=True)

        router = AlertRouter()
        router.register(failing).register(working)
        await router.dispatch(SAMPLE_PAYLOAD)

        working.send.assert_called_once()

    async def test_register_returns_self_for_chaining(self):
        router = AlertRouter()
        ch = AsyncMock()
        result = router.register(ch)
        assert result is router
        assert ch in router.channels


@pytest.mark.asyncio
class TestSlackChannel:
    async def test_sends_post_request_to_webhook(self):
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_response
            )
            result = await channel.send(SAMPLE_PAYLOAD)
            assert result is True

    async def test_block_decision_uses_red_color(self):
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
        captured = {}

        async def capture_post(url, json, **kwargs):
            captured["body"] = json
            r = MagicMock()
            r.status_code = 200
            return r

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = capture_post
            await channel.send(SAMPLE_PAYLOAD)
            assert captured["body"]["attachments"][0]["color"] == "#e01e5a"

    async def test_patched_decision_uses_amber_color(self):
        payload = AlertPayload(
            **{**SAMPLE_PAYLOAD.__dict__, "decision": "PATCHED", "mutation_count": 2}
        )
        channel = SlackChannel(webhook_url="https://hooks.slack.com/test")
        captured = {}

        async def capture_post(url, json, **kwargs):
            captured["body"] = json
            r = MagicMock()
            r.status_code = 200
            return r

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = capture_post
            await channel.send(payload)
            assert captured["body"]["attachments"][0]["color"] == "#f2c744"


class TestSQSChannel:
    def test_sends_message_to_queue(self):
        channel = SQSChannel(
            queue_url="https://sqs.ap-south-1.amazonaws.com/123/ace-alerts"
        )
        with patch.object(channel.client, "send_message") as mock_send:
            import asyncio

            asyncio.run(channel.send(SAMPLE_PAYLOAD))
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args[1]
            assert (
                call_kwargs["QueueUrl"]
                == "https://sqs.ap-south-1.amazonaws.com/123/ace-alerts"
            )

    def test_message_body_includes_all_fields(self):
        channel = SQSChannel(
            queue_url="https://sqs.ap-south-1.amazonaws.com/123/ace-alerts"
        )
        captured = {}

        with patch.object(
            channel.client,
            "send_message",
            side_effect=lambda **kw: captured.update(kw),
        ):
            import asyncio

            asyncio.run(channel.send(SAMPLE_PAYLOAD))
            body = json.loads(captured["MessageBody"])
            assert body["repo"] == "org/service"
            assert body["decision"] == "BLOCK"
            assert body["source"] == "ace-rhg"
