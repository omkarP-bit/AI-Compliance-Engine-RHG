import asyncio
import json

from ace.alerts.channels.slack import SlackChannel
from ace.alerts.router import AlertPayload, AlertRouter, AlertSeverity

_router: AlertRouter | None = None


def _get_router() -> AlertRouter:
    global _router
    if _router is None:
        _router = AlertRouter()
        _router.register(SlackChannel())
    return _router


def handler(event, context):
    router = _get_router()
    for record in event.get("Records", []):
        body = json.loads(record["body"])
        payload = AlertPayload(
            event_type=body["event_type"],
            pipeline_id=body["pipeline_id"],
            repo=body["repo"],
            environment=body["environment"],
            severity=AlertSeverity(body["severity"]),
            findings_count=body["findings_count"],
            blocking_rules=body["blocking_rules"],
            decision=body["decision"],
            report_url=body["report_url"],
            mutation_count=body.get("mutation_count", 0),
            escalation_reason=body.get("escalation_reason", ""),
        )
        asyncio.run(router.dispatch(payload))
    return {"statusCode": 200}
