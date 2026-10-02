import os

import httpx

from ace.notifier.mutation_notifier import MutationEvent

SEVERITY_EMOJI = {"CRITICAL": ":red_circle:", "HIGH": ":large_yellow_circle:", "MEDIUM": ":large_blue_circle:"}
COMPAT_EMOJI = {"COMPATIBLE": ":white_check_mark:", "INCOMPATIBLE": ":x:", "SKIPPED": ":heavy_minus_sign:"}

MUTATION_COLOR = "#f2c744"


class SlackMutationNotifier:
    """Sends a structured Block Kit alert for every OPA auto-mutation."""

    def __init__(self, webhook_url: str | None = None):
        self.webhook = webhook_url or os.environ.get("SLACK_WEBHOOK_URL", "")

    async def send(self, event: MutationEvent) -> bool:
        if not self.webhook:
            return False
        blocks = self._build_blocks(event)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.webhook,
                json={"attachments": [{"color": MUTATION_COLOR, "blocks": blocks}]},
                timeout=10.0,
            )
            return resp.status_code == 200

    def _build_blocks(self, e: MutationEvent) -> list[dict]:
        emoji = SEVERITY_EMOJI.get(e.rule_severity.upper(), ":white_circle:")
        compat = COMPAT_EMOJI.get(e.compatibility_verdict.upper(), ":heavy_minus_sign:")

        changes_text = "\n".join(
            f"  *{p.get('path', '?')}*\n    `{p.get('before', '(none)')}` -> `{p.get('after', p.get('value', ''))}`"
            for p in e.patches
        )

        return [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} ACE Auto-Mutation — {e.repo}"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Rule:*\n`{e.rule_id}` ({e.rule_severity})"},
                    {"type": "mrkdwn", "text": f"*Artifact:*\n`{e.artifact_name}`"},
                    {"type": "mrkdwn", "text": f"*Branch → Env:*\n`{e.branch}` → `{e.environment}`"},
                    {"type": "mrkdwn", "text": f"*Compatibility:*\n{compat} {e.compatibility_verdict}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Changes applied ({len(e.patches)} patches):*\n{changes_text}",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Full Diff"},
                        "url": e.diff_url or e.review_url,
                        "style": "primary",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Review / Override"},
                        "url": e.review_url,
                    },
                ],
            },
        ]

    def build_blocks(self, e: MutationEvent) -> list[dict]:
        return self._build_blocks(e)