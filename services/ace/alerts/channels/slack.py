import os

import httpx

from ace.alerts.router import AlertChannel, AlertPayload


SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH": ":large_yellow_circle:",
    "MEDIUM": ":large_blue_circle:",
}

DECISION_COLOR = {
    "ALLOW": "#36a64f",
    "BLOCK": "#e01e5a",
    "PATCHED": "#f2c744",
}


class SlackChannel(AlertChannel):
    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or os.environ["SLACK_WEBHOOK_URL"]

    async def send(self, payload: AlertPayload) -> bool:
        emoji = SEVERITY_EMOJI.get(payload.severity, ":white_circle:")
        color = DECISION_COLOR.get(payload.decision, "#cccccc")
        blocks = self._build_blocks(payload, emoji)

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.webhook_url,
                json={"attachments": [{"color": color, "blocks": blocks}]},
                timeout=10.0,
            )
            return resp.status_code == 200

    def _build_blocks(self, p: AlertPayload, emoji: str) -> list[dict]:
        decision_label = {
            "ALLOW": "Deployment allowed",
            "BLOCK": "Deployment blocked",
            "PATCHED": "Auto-patched and allowed",
        }.get(p.decision, p.decision)

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} ACE Security Gate — {p.repo}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Decision:*\n{decision_label}"},
                    {"type": "mrkdwn", "text": f"*Environment:*\n`{p.environment}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{p.severity}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Findings:*\n{p.findings_count} violations",
                    },
                ],
            },
        ]

        if p.blocking_rules:
            rules_text = "\n".join(f"• `{r}`" for r in p.blocking_rules[:5])
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Blocking rules:*\n{rules_text}",
                    },
                }
            )

        if p.mutation_count > 0:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Auto-mutations applied:* {p.mutation_count} patches",
                    },
                }
            )

        if p.escalation_reason:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f":warning: *Escalation reason:* {p.escalation_reason}",
                    },
                }
            )

        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Full Report"},
                        "url": p.report_url,
                        "style": "primary",
                    }
                ],
            }
        )

        return blocks
