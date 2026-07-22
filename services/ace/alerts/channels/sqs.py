import json
import os
from datetime import datetime, timezone

from ace.alerts.router import AlertChannel, AlertPayload


class SQSChannel(AlertChannel):
    def __init__(self, queue_url: str | None = None, region: str = "ap-south-1"):
        import boto3

        self.queue_url = queue_url or os.environ["SQS_ALERT_QUEUE_URL"]
        self.client = boto3.client("sqs", region_name=region)

    async def send(self, payload: AlertPayload) -> bool:
        message = {
            "version": "1.0",
            "source": "ace-rhg",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": payload.event_type,
            "pipeline_id": payload.pipeline_id,
            "repo": payload.repo,
            "environment": payload.environment,
            "severity": payload.severity,
            "decision": payload.decision,
            "findings_count": payload.findings_count,
            "blocking_rules": payload.blocking_rules,
            "report_url": payload.report_url,
            "mutation_count": payload.mutation_count,
            "escalation_reason": payload.escalation_reason,
        }
        self.client.send_message(
            QueueUrl=self.queue_url,
            MessageBody=json.dumps(message),
            MessageAttributes={
                "Severity": {
                    "StringValue": payload.severity,
                    "DataType": "String",
                },
                "Decision": {
                    "StringValue": payload.decision,
                    "DataType": "String",
                },
            },
        )
        return True
