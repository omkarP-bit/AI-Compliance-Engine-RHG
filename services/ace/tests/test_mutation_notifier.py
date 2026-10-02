from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import ace.notifier.mutation_notifier as nm
from ace.notifier.email_notifier import EmailMutationNotifier
from ace.notifier.mutation_notifier import MutationEvent, MutationNotifier
from ace.notifier.slack_notifier import SlackMutationNotifier

SAMPLE_PATCHES = [
    {
        "op": "replace",
        "path": "/spec/containers/0/securityContext/privileged",
        "before": True,
        "after": False,
    },
    {
        "op": "add",
        "path": "/spec/containers/0/securityContext/runAsNonRoot",
        "before": None,
        "after": True,
    },
]

SAMPLE_EVENT = MutationEvent(
    pipeline_id="pipe-001",
    repo="org/payments-service",
    branch="main",
    environment="production",
    rule_id="CIS-K8S-5.2.1",
    rule_severity="HIGH",
    rule_description="Privileged container detected",
    artifact_name="k8s/deployment.yaml",
    patches=SAMPLE_PATCHES,
    compatibility_verdict="COMPATIBLE",
    diff_url="http://dashboard/diff/001",
    review_url="http://dashboard/review/001",
)


@pytest.mark.asyncio
class TestMutationNotifier:
    async def test_notifies_all_channels_on_high_severity(self):
        notifier = MutationNotifier()
        notifier.slack.send = AsyncMock(return_value=True)
        notifier.email.send = AsyncMock(return_value=True)
        results = await notifier.notify(SAMPLE_EVENT)
        assert results["slack"] is True
        assert results["email"] is True
        notifier.slack.send.assert_called_once()
        notifier.email.send.assert_called_once()

    async def test_skips_below_configured_threshold(self):
        original = nm.NOTIFY_ON_SEVERITY
        nm.NOTIFY_ON_SEVERITY = {"CRITICAL"}
        try:
            notifier = MutationNotifier()
            notifier.slack.send = AsyncMock(return_value=True)
            results = await notifier.notify(SAMPLE_EVENT)
            assert results == {}
            notifier.slack.send.assert_not_called()
        finally:
            nm.NOTIFY_ON_SEVERITY = original

    async def test_continues_if_slack_fails(self):
        notifier = MutationNotifier()
        notifier.slack.send = AsyncMock(side_effect=Exception("Slack down"))
        notifier.email.send = AsyncMock(return_value=True)
        results = await notifier.notify(SAMPLE_EVENT)
        assert results["slack"] is False
        assert results["email"] is True

    async def test_slack_block_kit_contains_all_fields(self):
        slack = SlackMutationNotifier(webhook_url="https://hooks.slack.com/test")
        captured = {}

        async def capture(url, json, **kw):
            captured["body"] = json
            r = MagicMock()
            r.status_code = 200
            return r

        with patch("httpx.AsyncClient") as mc:
            mc.return_value.__aenter__.return_value.post = capture
            await slack.send(SAMPLE_EVENT)
        blocks = captured["body"]["attachments"][0]["blocks"]
        full_text = str(blocks)
        assert "CIS-K8S-5.2.1" in full_text
        assert "k8s/deployment.yaml" in full_text
        assert "COMPATIBLE" in full_text
        assert "http://dashboard/diff/001" in full_text
        assert "privileged" in full_text

    async def test_slack_returns_false_without_webhook(self):
        slack = SlackMutationNotifier(webhook_url="")
        assert await slack.send(SAMPLE_EVENT) is False

    def test_email_body_contains_change_log(self):
        email = EmailMutationNotifier()
        body = email._build_body(SAMPLE_EVENT)
        assert "CIS-K8S-5.2.1" in body
        assert "/spec/containers/0/securityContext/privileged" in body
        assert "COMPATIBLE" in body
        assert "http://dashboard/review/001" in body
        assert "True" in body

    async def test_email_returns_false_when_not_configured(self):
        email = EmailMutationNotifier()
        email.recipients = []
        assert await email.send(SAMPLE_EVENT) is False