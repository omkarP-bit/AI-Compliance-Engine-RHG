import os

NOTIFY_ON_SEVERITY = set(
    s.strip().upper()
    for s in os.environ.get("NOTIFY_ON_SEVERITY", "CRITICAL,HIGH").split(",")
    if s.strip()
)


class MutationEvent:
    """Structured record of a single OPA auto-mutation."""

    def __init__(
        self,
        pipeline_id: str,
        repo: str,
        branch: str,
        environment: str,
        rule_id: str,
        rule_severity: str,
        rule_description: str,
        artifact_name: str,
        patches: list[dict],
        compatibility_verdict: str = "SKIPPED",
        diff_url: str = "",
        review_url: str = "",
    ):
        self.pipeline_id = pipeline_id
        self.repo = repo
        self.branch = branch
        self.environment = environment
        self.rule_id = rule_id
        self.rule_severity = rule_severity
        self.rule_description = rule_description
        self.artifact_name = artifact_name
        self.patches = patches
        self.compatibility_verdict = compatibility_verdict
        self.diff_url = diff_url
        self.review_url = review_url


class MutationNotifier:
    """Orchestrates all notification channels for OPA auto-mutations."""

    def __init__(self):
        from ace.notifier.email_notifier import EmailMutationNotifier
        from ace.notifier.slack_notifier import SlackMutationNotifier

        self.slack = SlackMutationNotifier()
        self.email = EmailMutationNotifier()

    async def notify(self, event: MutationEvent) -> dict[str, bool]:
        if event.rule_severity.upper() not in NOTIFY_ON_SEVERITY:
            return {}

        results: dict[str, bool] = {}
        try:
            results["slack"] = await self.slack.send(event)
        except Exception:
            results["slack"] = False
        try:
            results["email"] = await self.email.send(event)
        except Exception:
            results["email"] = False
        return results