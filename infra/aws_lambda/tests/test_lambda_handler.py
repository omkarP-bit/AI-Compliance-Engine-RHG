import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

from ace.alerts.router import AlertRouter
from ace.main import app
from fastapi.testclient import TestClient


class TestAceScanHandler:
    def setup_method(self):
        self.client = TestClient(app)

    def test_handler_accepts_api_gateway_event(self):
        with patch(
            "ace.engine.opa_client.OPAClient.health",
            new_callable=AsyncMock,
            return_value=False,
        ):
            resp = self.client.post(
                "/ace/scan",
                json={
                    "pipeline_id": "lambda-test",
                    "environment": "production",
                    "artifacts": [],
                },
            )
            assert resp.status_code in [200, 503]

    def test_handler_returns_503_when_opa_down(self):
        with patch(
            "ace.engine.opa_client.OPAClient.health",
            new_callable=AsyncMock,
            return_value=False,
        ):
            resp = self.client.post(
                "/ace/scan",
                json={
                    "pipeline_id": "lambda-test",
                    "environment": "production",
                    "artifacts": [],
                },
            )
            assert resp.status_code == 503

    def test_health_endpoint(self):
        resp = self.client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestAlertDispatcher:
    def test_dispatches_sqs_record(self):
        from infra.aws_lambda.handlers.alert_dispatcher_handler import handler

        event = {
            "Records": [
                {
                    "body": json.dumps(
                        {
                            "event_type": "gate.decision",
                            "pipeline_id": "pipe-001",
                            "repo": "org/svc",
                            "environment": "production",
                            "severity": "HIGH",
                            "findings_count": 2,
                            "blocking_rules": ["CIS-K8S-5.2.1"],
                            "decision": "BLOCK",
                            "report_url": "http://dashboard/1",
                            "mutation_count": 0,
                            "escalation_reason": "",
                        }
                    )
                }
            ]
        }
        with (
            patch.object(AlertRouter, "dispatch", new_callable=AsyncMock),
            patch.dict(os.environ, {"SLACK_WEBHOOK_URL": "https://hooks.slack.com/test"}),
        ):
            result = handler(event, MagicMock())
            assert result["statusCode"] == 200
