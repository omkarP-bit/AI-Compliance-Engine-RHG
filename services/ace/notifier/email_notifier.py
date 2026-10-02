import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from ace.notifier.mutation_notifier import MutationEvent


class EmailMutationNotifier:
    """Sends a plain-text structured email for every OPA auto-mutation (optional)."""

    def __init__(self):
        self.host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
        self.port = int(os.environ.get("SMTP_PORT", "587"))
        self.user = os.environ.get("SMTP_USER", "")
        self.password = os.environ.get("SMTP_PASSWORD", "")
        self.recipients = [r.strip() for r in os.environ.get("OPS_EMAIL_LIST", "").split(",") if r.strip()]

    async def send(self, event: MutationEvent) -> bool:
        if not self.recipients or not self.user:
            return False

        subject = f"[ACE] Auto-mutation — {event.repo} — {event.rule_id} ({event.rule_severity})"
        body = self._build_body(event)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.user
        msg["To"] = ", ".join(self.recipients)
        msg.attach(MIMEText(body, "plain"))

        try:
            import aiosmtplib

            await aiosmtplib.send(
                msg,
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                start_tls=True,
            )
            return True
        except Exception:
            return False

    def _build_body(self, e: MutationEvent) -> str:
        changes = "\n".join(
            f"  {i + 1}. {p.get('path', '?')}: {p.get('before', '(none)')} → {p.get('after', p.get('value', ''))}"
            for i, p in enumerate(e.patches)
        )
        return f"""ACE has automatically patched a security violation in your pipeline.
No action required unless you wish to review or override.

Rule:         {e.rule_id} — {e.rule_description} ({e.rule_severity})
Artifact:     {e.artifact_name}
Repo:         {e.repo}
Branch:       {e.branch}
Environment:  {e.environment}

Patches applied:
{changes}

Compatibility check: {e.compatibility_verdict}

Full diff:    {e.diff_url}
Override:     {e.review_url}

---
This notification was generated automatically by ACE+RHG.
To change notification thresholds, set NOTIFY_ON_SEVERITY.
"""

    def build_body(self, e: MutationEvent) -> str:
        return self._build_body(e)