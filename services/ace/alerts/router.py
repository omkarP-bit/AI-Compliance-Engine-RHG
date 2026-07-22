from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class AlertSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass
class AlertPayload:
    event_type: str
    pipeline_id: str
    repo: str
    environment: str
    severity: AlertSeverity
    findings_count: int
    blocking_rules: list[str]
    decision: str
    report_url: str
    mutation_count: int = 0
    escalation_reason: str = ""


class AlertChannel(Protocol):
    async def send(self, payload: AlertPayload) -> bool: ...


class AlertRouter:
    def __init__(self):
        self.channels: list[AlertChannel] = []

    def register(self, channel: AlertChannel) -> "AlertRouter":
        self.channels.append(channel)
        return self

    async def dispatch(self, payload: AlertPayload) -> None:
        for channel in self.channels:
            try:
                await channel.send(payload)
            except Exception as e:
                import structlog

                structlog.get_logger().error(
                    "alert_channel_failed",
                    channel=type(channel).__name__,
                    error=str(e),
                )
