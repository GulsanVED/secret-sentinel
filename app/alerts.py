"""
Alert delivery: email (SMTP), Slack, generic webhook, console.

Every alert is always recorded in the DB, so the UI never misses one — these
functions are about pushing it somewhere external too.

Email is sent as a DIGEST by default: one message per scan listing everything
that changed, instead of one message per finding (which turns a first scan of
a leaky repo into 40 emails). Set ALERT_EMAIL_MODE=per_event for one email per
event instead.

Environment variables
---------------------
  SMTP_HOST, SMTP_PORT            SMTP server (port 465 => implicit SSL,
                                  587/25 => STARTTLS when offered)
  SMTP_USER, SMTP_PASSWORD        credentials (optional for local relays)
  SMTP_STARTTLS=false             disable STARTTLS explicitly
  ALERT_EMAIL_FROM, ALERT_EMAIL_TO   addresses (TO may be comma-separated)
  ALERT_EMAIL_MODE=digest|per_event
  SLACK_WEBHOOK_URL               Slack incoming webhook
  ALERT_WEBHOOK_URL               generic JSON POST
"""
import html
import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate
from typing import Dict, List, Optional

logger = logging.getLogger("secret-sentinel.alerts")

SEVERITY_COLORS = {"critical": "#c62828", "high": "#ef6c00", "medium": "#f9a825", "low": "#616161"}
KIND_LABELS = {
    "new_secret": "Secret exposed",
    "secret_removed": "Secret removed",
    "secret_reintroduced": "Secret re-introduced",
    "history_secret": "Secret found in git history",
    "scan_error": "Scan error",
}


# --------------------------------------------------------------------------
# Configuration helpers
# --------------------------------------------------------------------------

def email_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("ALERT_EMAIL_TO"))


def email_mode() -> str:
    return (os.environ.get("ALERT_EMAIL_MODE") or "digest").strip().lower()


def channel_status() -> Dict[str, bool]:
    return {
        "email": email_configured(),
        "slack": bool(os.environ.get("SLACK_WEBHOOK_URL")),
        "webhook": bool(os.environ.get("ALERT_WEBHOOK_URL")),
    }


def _recipients() -> List[str]:
    return [a.strip() for a in (os.environ.get("ALERT_EMAIL_TO") or "").split(",") if a.strip()]


# --------------------------------------------------------------------------
# SMTP
# --------------------------------------------------------------------------

def send_email(subject: str, text_body: str, html_body: Optional[str] = None) -> bool:
    """Send one email. Returns True on success. Never raises — alerting must not
    break a scan."""
    host = os.environ.get("SMTP_HOST")
    to_addrs = _recipients()
    if not host or not to_addrs:
        return False

    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("ALERT_EMAIL_FROM") or user or "secret-sentinel@localhost"
    use_starttls = (os.environ.get("SMTP_STARTTLS", "true").strip().lower() != "false")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to_addrs)
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=30, context=ssl.create_default_context()) as s:
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as s:
                s.ehlo()
                if use_starttls and s.has_extn("starttls"):
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                if user and password:
                    s.login(user, password)
                s.send_message(msg)
        logger.info("Email sent to %s: %s", ", ".join(to_addrs), subject)
        return True
    except Exception as e:
        logger.error("Email send failed (%s:%s): %s", host, port, e)
        return False


# --------------------------------------------------------------------------
# Digest email (one per scan)
# --------------------------------------------------------------------------

def send_scan_digest(repo_label: str, repo_url: str, events: List[Dict], scan_summary: str) -> bool:
    """events: [{"kind", "severity", "description", "file_path", "line_number",
    "matched_text", "link"}]. Sent after a scan that produced changes."""
    if not email_configured() or not events:
        return False

    counts = {k: sum(1 for e in events if e["kind"] == k) for k in KIND_LABELS}
    new, removed, back = counts["new_secret"], counts["secret_removed"], counts["secret_reintroduced"]
    worst = next((s for s in ("critical", "high", "medium", "low")
                  if any(e["severity"] == s and e["kind"] != "secret_removed" for e in events)), None)

    bits = []
    if new:
        bits.append(f"{new} exposed")
    if back:
        bits.append(f"{back} re-introduced")
    if removed:
        bits.append(f"{removed} removed")
    prefix = "🔴" if worst in ("critical", "high") else ("🟡" if worst else "✅")
    subject = f"{prefix} {repo_label}: {', '.join(bits)}"
    if worst:
        subject += f" ({worst.upper()})"

    # ---- plain text ----
    lines = [f"Secret Sentinel — {repo_label}", repo_url, "", scan_summary, ""]
    for kind in ("new_secret", "secret_reintroduced", "secret_removed"):
        group = [e for e in events if e["kind"] == kind]
        if not group:
            continue
        lines.append(f"{KIND_LABELS[kind].upper()} ({len(group)})")
        for e in group:
            loc = e["file_path"] + (f":{e['line_number']}" if e.get("line_number") else "")
            lines.append(f"  [{e['severity'].upper()}] {e['description']}")
            lines.append(f"    {loc}   value: {e['matched_text']}")
            if e.get("link"):
                lines.append(f"    {e['link']}")
        lines.append("")
    if new or back:
        lines += ["Deleting a secret from the repo does not make it safe — it stays in git",
                  "history and in any clones or forks. Rotate the credential if it was real.", ""]
    text_body = "\n".join(lines)

    # ---- html ----
    def rows(kind: str) -> str:
        group = [e for e in events if e["kind"] == kind]
        if not group:
            return ""
        out = [f'<tr><td colspan="3" style="padding:14px 12px 6px;font:600 13px system-ui;color:#444">'
               f'{html.escape(KIND_LABELS[kind])} ({len(group)})</td></tr>']
        for e in group:
            color = SEVERITY_COLORS.get(e["severity"], "#616161")
            loc = html.escape(e["file_path"]) + (f":{e['line_number']}" if e.get("line_number") else "")
            loc_html = f'<a href="{html.escape(e["link"])}" style="color:#1565c0;text-decoration:none">{loc}</a>' \
                if e.get("link") else loc
            out.append(
                f'<tr style="border-top:1px solid #eee">'
                f'<td style="padding:10px 12px;vertical-align:top">'
                f'<span style="background:{color};color:#fff;border-radius:4px;padding:2px 7px;'
                f'font:700 10px system-ui;text-transform:uppercase">{html.escape(e["severity"])}</span></td>'
                f'<td style="padding:10px 12px;font:13px system-ui;color:#222">{html.escape(e["description"])}'
                f'<div style="font:12px ui-monospace,Menlo,monospace;color:#666;margin-top:3px">{loc_html}</div></td>'
                f'<td style="padding:10px 12px;font:12px ui-monospace,Menlo,monospace;color:#444;'
                f'vertical-align:top;white-space:nowrap">{html.escape(e["matched_text"])}</td></tr>')
        return "".join(out)

    warning = ""
    if new or back:
        warning = ('<p style="font:13px system-ui;color:#8a4b00;background:#fff8e1;border:1px solid #ffe082;'
                   'border-radius:6px;padding:10px 12px">Deleting a secret from the repo does not make it safe: '
                   'it remains in git history and in any clones or forks. <b>Rotate the credential</b> '
                   'if it was real.</p>')
    html_body = f"""<html><body style="margin:0;background:#f5f6f8;padding:22px">
<div style="max-width:680px;margin:0 auto;background:#fff;border:1px solid #e3e5e9;border-radius:10px;overflow:hidden">
  <div style="padding:16px 18px;border-bottom:1px solid #e3e5e9">
    <div style="font:600 16px system-ui;color:#111">Secret Sentinel</div>
    <div style="font:13px system-ui;color:#555;margin-top:3px">
      <a href="{html.escape(repo_url)}" style="color:#1565c0;text-decoration:none">{html.escape(repo_label)}</a>
    </div>
  </div>
  <table style="width:100%;border-collapse:collapse">{rows("new_secret")}{rows("secret_reintroduced")}{rows("secret_removed")}</table>
  <div style="padding:14px 18px;border-top:1px solid #e3e5e9">
    {warning}
    <div style="font:12px system-ui;color:#888">{html.escape(scan_summary)}</div>
  </div>
</div></body></html>"""

    return send_email(subject, text_body, html_body)


# --------------------------------------------------------------------------
# Outbound HTTP for CI (stdlib only)
# --------------------------------------------------------------------------

def post_json(url: str, payload: Dict, headers: Optional[Dict[str, str]] = None, timeout: int = 15) -> int:
    """POST JSON with urllib and return the HTTP status. Only http(s) URLs are
    allowed: urlopen would otherwise also open file:// and other schemes taken
    from a mistyped or malicious setting."""
    import json
    import urllib.parse
    import urllib.request

    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"refusing to POST to a non-http(s) URL: {url!r}")
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    # Bandit B310 (urlopen accepts any scheme) is handled by the check above.
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310
        return r.status


# --------------------------------------------------------------------------
# Slack digest for CI (stdlib only, so CI jobs need no pip install)
# --------------------------------------------------------------------------

def send_slack_digest(repo_label: str, events: List[Dict], scan_summary: str,
                      url: Optional[str] = None) -> bool:
    """One Slack message per CI scan. Values are the masked form only."""
    import urllib.error

    url = url or os.environ.get("SLACK_WEBHOOK_URL")
    if not url or not events:
        return False
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    lines = [f":rotating_light: *Secret Sentinel* — `{repo_label}`", scan_summary, ""]
    for e in sorted(events, key=lambda e: order.get(e["severity"], 9))[:25]:
        loc = e["file_path"] + (f":{e['line_number']}" if e.get("line_number") else "")
        loc = f"<{e['link']}|{loc}>" if e.get("link") else f"`{loc}`"
        lines.append(f"• *{e['severity'].upper()}* {e['description']} — {loc} — `{e['matched_text']}`")
    if len(events) > 25:
        lines.append(f"…and {len(events) - 25} more (see the CI job summary).")
    try:
        post_json(url, {"text": "\n".join(lines)})
        return True
    except (urllib.error.URLError, OSError, ValueError) as e:
        logger.error("Slack webhook failed: %s", e)
        return False


# --------------------------------------------------------------------------
# Per-event alerts (console always; Slack/webhook/email as configured)
# --------------------------------------------------------------------------

def send_alert(repo_label: str, kind: str, message: str) -> None:
    print(f"[ALERT] ({kind}) {repo_label}: {message}", flush=True)

    slack_url = os.environ.get("SLACK_WEBHOOK_URL")
    webhook_url = os.environ.get("ALERT_WEBHOOK_URL")
    if slack_url or webhook_url:
        import httpx  # imported lazily so CI-only email use needs no dependencies
        if slack_url:
            try:
                httpx.post(slack_url, json={"text": f"*[{KIND_LABELS.get(kind, kind)}]* `{repo_label}`\n{message}"},
                           timeout=10)
            except Exception as e:
                logger.error("Slack webhook failed: %s", e)
        if webhook_url:
            try:
                httpx.post(webhook_url, json={"repo": repo_label, "kind": kind, "message": message}, timeout=10)
            except Exception as e:
                logger.error("Generic webhook failed: %s", e)

    if email_configured() and email_mode() == "per_event":
        send_email(f"[{KIND_LABELS.get(kind, kind)}] {repo_label}", f"{repo_label}\n\n{message}")


def send_test_email() -> bool:
    return send_email(
        "Secret Sentinel test email",
        "This is a test from Secret Sentinel. If you received this, email alerting works.",
        '<p style="font:14px system-ui">This is a test from <b>Secret Sentinel</b>. '
        'If you received this, email alerting works.</p>')
