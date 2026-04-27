"""Send HTML email via local sendmail."""

from __future__ import annotations

import subprocess
from email.mime.text import MIMEText

from . import log


def send(subject: str, body: str, *, to: str, sender: str) -> None:
    msg = MIMEText(body, "html")
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    try:
        proc = subprocess.run(
            ["/usr/sbin/sendmail", "-t"],
            input=msg.as_string(),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            log.emit("EMAIL_SENT", to=to, subject=subject)
        else:
            log.error("EMAIL_FAILED", stderr=proc.stderr[:200])
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error("EMAIL_ERROR", error=str(e))
