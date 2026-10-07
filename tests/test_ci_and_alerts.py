"""
Tests for the real-time additions: SMTP email delivery, the CI CLI
(`scan-path`, including git diff mode), and the webhook endpoints.

Run:  python3 -m tests.test_ci_and_alerts
The email tests run against a fake SMTP server on localhost — nothing leaves
the machine.
"""
import email
import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

FAILURES = []


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


# --------------------------------------------------------------------------
# Minimal SMTP server: speaks just enough to accept one message.
# --------------------------------------------------------------------------

class FakeSMTP(threading.Thread):
    daemon = True

    def __init__(self):
        super().__init__()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.messages = []
        self.auth_seen = False

    def run(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        f = conn.makefile("rwb")
        conn.sendall(b"220 fake ESMTP\r\n")
        data_mode, body = False, []
        while True:
            line = f.readline()
            if not line:
                break
            if data_mode:
                if line.strip() == b".":
                    self.messages.append(b"".join(body).decode("utf-8", "replace"))
                    body, data_mode = [], False
                    conn.sendall(b"250 OK queued\r\n")
                else:
                    body.append(line)
                continue
            cmd = line.decode("utf-8", "replace").strip()
            up = cmd.upper()
            if up.startswith("EHLO") or up.startswith("HELO"):
                conn.sendall(b"250-fake\r\n250 AUTH PLAIN LOGIN\r\n")
            elif up.startswith("AUTH"):
                self.auth_seen = True
                conn.sendall(b"235 authenticated\r\n")
            elif up.startswith(("MAIL", "RCPT")):
                conn.sendall(b"250 OK\r\n")
            elif up == "DATA":
                data_mode = True
                conn.sendall(b"354 end with .\r\n")
            elif up == "QUIT":
                conn.sendall(b"221 bye\r\n")
                break
            else:
                conn.sendall(b"250 OK\r\n")
        conn.close()


def test_email(smtp):
    print("1) Email delivery over SMTP")
    from app import alerts
    os.environ.update(SMTP_HOST="127.0.0.1", SMTP_PORT=str(smtp.port), SMTP_USER="bot@example.com",
                      SMTP_PASSWORD="pw", ALERT_EMAIL_TO="me@example.com, ops@example.com",
                      ALERT_EMAIL_FROM="bot@example.com", ALERT_EMAIL_MODE="digest")
    check("email_configured()", alerts.email_configured())

    events = [
        {"kind": "new_secret", "severity": "critical", "description": "Database connection URL with embedded credentials",
         "file_path": ".env", "line_number": 3, "matched_text": "post****1234",
         "link": "https://github.com/acme/demo/blob/abc123/.env#L3"},
        {"kind": "new_secret", "severity": "high", "description": "Hard-coded secret / password / API key",
         "file_path": "config.py", "line_number": 11, "matched_text": "sk_l****wxyz", "link": None},
        {"kind": "secret_removed", "severity": "medium", "description": "Database connection URL",
         "file_path": "old.env", "line_number": 1, "matched_text": "mysq****test", "link": None},
    ]
    ok = alerts.send_scan_digest("acme/demo", "https://github.com/acme/demo", events,
                                 "Incremental scan abc1234..def5678: 2 new, 1 removed, 5 active")
    check("digest send returned True", ok)
    check("server received the message", len(smtp.messages) == 1, len(smtp.messages))
    if not smtp.messages:
        return
    msg = email.message_from_string(smtp.messages[-1])
    check("authenticated", smtp.auth_seen)
    check("subject names repo + counts",
          "acme/demo" in msg["Subject"] and "2 exposed" in msg["Subject"] and "CRITICAL" in msg["Subject"],
          msg["Subject"])
    check("both recipients", "me@example.com" in msg["To"] and "ops@example.com" in msg["To"], msg["To"])
    check("multipart (text + html)", msg.is_multipart())
    parts = {p.get_content_type(): p.get_payload(decode=True).decode() for p in msg.walk() if not p.is_multipart()}
    check("has text/plain and text/html", set(parts) == {"text/plain", "text/html"}, list(parts))
    text, html_body = parts.get("text/plain", ""), parts.get("text/html", "")
    check("text lists the finding", ".env:3" in text and "post****1234" in text)
    check("text groups removals", "SECRET REMOVED (1)" in text, text[:200])
    check("text warns about git history", "git" in text and "Rotate" in text)
    check("html links to the line", 'blob/abc123/.env#L3' in html_body)
    check("html shows severity badge", "critical" in html_body.lower())
    check("no unmasked secret in either part",
          "S3cretPass" not in text and "S3cretPass" not in html_body)

    # per_event mode
    smtp.messages.clear()
    os.environ["ALERT_EMAIL_MODE"] = "per_event"
    alerts.send_alert("acme/demo", "new_secret", "[HIGH] test finding in a.py:1 — value: ab****yz")
    check("per_event mode sends one email per alert", len(smtp.messages) == 1, len(smtp.messages))
    os.environ["ALERT_EMAIL_MODE"] = "digest"

    # a digest with no events sends nothing
    smtp.messages.clear()
    check("no email when nothing changed", alerts.send_scan_digest("acme/demo", "u", [], "s") is False
          and not smtp.messages)

    # failure path must not raise
    os.environ["SMTP_HOST"] = "127.0.0.1"
    os.environ["SMTP_PORT"] = "1"      # nothing listening
    check("send failure returns False instead of raising", alerts.send_email("x", "y") is False)
    os.environ["SMTP_PORT"] = str(smtp.port)


def test_cli(smtp):
    print("2) CI CLI (scan-path) on a real git repo")
    from app.cli import main

    repo = Path(tempfile.mkdtemp())
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, check=True)
    run("init", "-q")
    run("config", "user.email", "t@t.t")
    run("config", "user.name", "t")

    (repo / "README.md").write_text("# hello\n")
    (repo / "safe.py").write_text("import os\nKEY = os.environ['API_KEY']\n")
    run("add", "-A"), run("commit", "-qm", "clean")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()

    # Clean repo -> exit 0
    code = main(["scan-path", str(repo), "--fail-on", "high"])
    check("clean repo exits 0", code == 0, code)

    # Now leak something
    (repo / ".env").write_text("DATABASE_URL=postgres://admin:S3cretPass@db.internal:5432/app\n")
    (repo / "deep" / "nested").mkdir(parents=True)
    (repo / "deep" / "nested" / "keys.yml").write_text("api_key: sk_live_51HabcdefghijklmnopQ\n")
    run("add", "-A"), run("commit", "-qm", "leak")

    code = main(["scan-path", str(repo), "--fail-on", "critical"])
    check("leaked repo exits 1 on --fail-on critical", code == 1, code)
    code = main(["scan-path", str(repo), "--fail-on", "none"])
    check("--fail-on none exits 0", code == 0, code)

    # JSON output
    import contextlib, io, json
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["scan-path", str(repo), "--json", "--fail-on", "none"])
    data = json.loads(buf.getvalue())
    rules = {f["rule_id"] for f in data["findings"]}
    check("json lists both secrets", rules == {"db-url-with-credentials", "stripe-key"}, rules)
    check("json masks the value", all("S3cretPass" not in f["value_masked"] for f in data["findings"]))
    check("nested dirs scanned", any(f["file_path"] == "deep/nested/keys.yml" for f in data["findings"]))

    # --diff-base: only files changed since `base`
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["scan-path", str(repo), "--diff-base", base, "--json", "--fail-on", "none"])
    d2 = json.loads(buf.getvalue())
    check("diff mode uses changed-files", d2["mode"] == "changed-files", d2["mode"])
    check("diff mode still finds both new secrets", len(d2["findings"]) == 2, d2["findings"])

    # An unchanged tree in diff mode finds nothing
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["scan-path", str(repo), "--diff-base", head, "--json", "--fail-on", "none"])
    check("no changes -> no findings", json.loads(buf.getvalue())["findings"] == [])

    # All-zero base (new branch) falls back to a full scan
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["scan-path", str(repo), "--diff-base", "0" * 40, "--json", "--fail-on", "none"])
    check("all-zero base falls back to full", json.loads(buf.getvalue())["mode"].startswith("full"))

    # Email from CI
    smtp.messages.clear()
    main(["scan-path", str(repo), "--label", "acme/demo", "--commit", "deadbeef" * 5,
          "--email", "--fail-on", "none"])
    check("CI scan emails the findings", len(smtp.messages) == 1, len(smtp.messages))
    if smtp.messages:
        body = smtp.messages[-1]
        check("CI email mentions the repo label", "acme/demo" in body)
        check("CI email links to the commit", "deadbeef" in body)

    # A real commit: the email names its author and says when the scan ran.
    smtp.messages.clear()
    main(["scan-path", str(repo), "--label", "acme/demo", "--email", "--fail-on", "none"])
    if smtp.messages:
        msg = email.message_from_string(smtp.messages[-1])
        text = next((part.get_payload(decode=True).decode() for part in msg.walk()
                     if part.get_content_type() == "text/plain"), "")
        check("CI email names the commit author", "Commit by t on " in text, text[-400:])
        check("CI email says when it was scanned", "Scanned " in text, text[-400:])
    else:
        check("CI email with a real commit was sent", False)

    # .git internals are never scanned
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["scan-path", str(repo), "--json", "--fail-on", "none"])
    check("no .git paths in results",
          not any(f["file_path"].startswith(".git/") for f in json.loads(buf.getvalue())["findings"]))

    # ci_scan.py wrapper: bare path argument
    proc = subprocess.run([sys.executable, "ci_scan.py", str(repo), "--fail-on", "none"],
                          capture_output=True, text=True, cwd=Path(__file__).resolve().parent.parent)
    check("ci_scan.py wrapper runs", proc.returncode == 0 and "findings: 2" in proc.stdout,
          proc.stdout[-200:] + proc.stderr[-200:])


def test_webhooks():
    print("3) Webhook endpoints")
    import asyncio
    import hashlib
    import hmac
    import json
    import tempfile as tf
    from http.server import ThreadingHTTPServer

    from tests import test_pipeline_e2e as e2e

    server = ThreadingHTTPServer(("127.0.0.1", 0), e2e.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    os.environ.update(GITHUB_API_URL=f"http://127.0.0.1:{port}/api",
                      GITHUB_RAW_URL=f"http://127.0.0.1:{port}/raw",
                      NO_PROXY="127.0.0.1", no_proxy="127.0.0.1",
                      GITHUB_WEBHOOK_SECRET="topsecret", ALERT_EMAIL_MODE="digest",
                      # the fake API has no git remote; history refresh is covered in test_history
                      HISTORY_SCAN_ON_PUSH="false")
    os.environ.pop("GITHUB_TOKEN", None)

    from app import db
    db.DB_PATH = Path(tf.mkdtemp()) / "wh.db"
    db.init_db()
    e2e.REPO.commits.clear()
    e2e.REPO.commit({".env": "DB_PASSWORD=LeakedPass123\n"})

    from fastapi import BackgroundTasks, HTTPException
    from app import main as srv
    routes = {(m, r.path): r.endpoint for r in srv.app.routes
              for m in (getattr(r, "methods", None) or ())}
    gh = routes[("POST", "/webhook/github")]
    ci = routes[("POST", "/webhook/ci")]

    # Start page at /, dashboard at /dashboard
    check("/ serves the start page", Path(routes[("GET", "/")]().path).name == "home.html")
    check("/dashboard serves the dashboard", Path(routes[("GET", "/dashboard")]().path).name == "index.html")

    def Request(body: bytes, headers: dict):  # noqa: N802 - mimics the class
        from starlette.requests import Request as StarletteRequest
        scope = {"type": "http", "method": "POST", "path": "/", "query_string": b"",
                 "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        return StarletteRequest(scope, receive)

    def run_bg(bg):
        asyncio.run(bg())

    def call(body: dict, event="push", secret="topsecret"):
        raw = json.dumps(body).encode()
        headers = {"X-GitHub-Event": event}
        if secret is not None:
            headers["X-Hub-Signature-256"] = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        bg = BackgroundTasks()
        res = asyncio.run(gh(Request(raw, headers), bg))
        return res, bg

    push = {"ref": "refs/heads/main", "after": e2e.REPO.head,
            "repository": {"full_name": "acme/demo", "default_branch": "main"}}

    # Bad signature rejected
    try:
        call(push, secret="wrong")
        check("rejects an invalid signature", False)
    except HTTPException as e:
        check("rejects an invalid signature", e.status_code == 401, e.status_code)

    # Missing signature rejected when a secret is configured
    try:
        call(push, secret=None)
        check("rejects a missing signature", False)
    except HTTPException as e:
        check("rejects a missing signature", e.status_code == 401, e.status_code)

    # ping
    res, _ = call({}, event="ping")
    check("answers the GitHub ping", res["ok"] and "reachable" in res["message"], res)

    # non-push events ignored
    res, _ = call(push, event="issues")
    check("ignores non-push events", res.get("ignored_event") == "issues", res)

    # tag push ignored
    res, bg = call({"ref": "refs/tags/v1", "repository": {"full_name": "acme/demo"}})
    check("ignores tag pushes", "ignored" in res and not bg.tasks, res)

    # Valid push for an unknown repo -> auto-register + scan
    res, bg = call(push)
    check("auto-registers an unknown repo", res.get("registering") == "https://github.com/acme/demo", res)
    run_bg(bg)
    active = db.list_findings(status="active")
    check("scan ran and found the secret", len(active) == 1 and active[0]["rule_id"] == "generic-secret-assignment",
          active)

    # Next push for the known repo -> incremental scan, no duplicate row
    e2e.REPO.commit({".env": "DB_PASSWORD=LeakedPass123\nSTRIPE=sk_live_51Habcdefghijklmnopq\n"})
    push["after"] = e2e.REPO.head
    res, bg = call(push)
    check("scans the registered repo", "scanning" in res, res)
    run_bg(bg)
    check("no duplicate repo rows", len(db.list_repos()) == 1, db.list_repos())
    check("new secret detected on push", len(db.list_findings(status="active")) == 2,
          db.list_findings(status="active"))

    # Push to an unmonitored branch is ignored by default
    res, bg = call({"ref": "refs/heads/feature-x", "repository": {"full_name": "acme/demo", "default_branch": "main"}})
    check("ignores unmonitored branches", "ignored" in res and not bg.tasks, res)

    # Unsigned mode (no secret configured) still works
    os.environ["GITHUB_WEBHOOK_SECRET"] = ""
    res, bg = call(push, secret=None)
    check("works without a configured secret", "scanning" in res, res)
    os.environ["GITHUB_WEBHOOK_SECRET"] = "topsecret"

    # CI webhook: token enforced
    os.environ["SENTINEL_TOKEN"] = "citoken"
    try:
        ci(srv.CiNotifyRequest(repo="acme/demo"), Request(b"", {}), BackgroundTasks())
        check("CI webhook rejects a bad token", False)
    except HTTPException as e:
        check("CI webhook rejects a bad token", e.status_code == 401, e.status_code)

    bg = BackgroundTasks()
    res = ci(srv.CiNotifyRequest(repo="acme/demo", commit="abc", findings=[{"severity": "high"}]),
             Request(b"", {"X-Sentinel-Token": "citoken"}), bg)
    check("CI webhook accepts a good token and rescans", res.get("rescanning") == "acme/demo", res)

    server.shutdown()


def test_tunnel():
    print("4) Public ngrok tunnel: webhooks only")
    import contextlib
    import io
    import sys
    import types
    from fastapi.testclient import TestClient
    from app import main as srv, serve, tunnel

    for k in ("SENTINEL_PUBLIC_URL", "NGROK_EXPOSE_DASHBOARD", "NGROK_DOMAIN", "NGROK_AUTHTOKEN"):
        os.environ.pop(k, None)
    client = TestClient(srv.app, base_url="http://localhost")
    public = {"host": "concrete-thank-kinetic.ngrok-free.dev", "x-forwarded-for": "140.82.115.1"}

    check("no tunnel: dashboard reachable as before", client.get("/api/repos").status_code == 200
          and client.get("/dashboard", headers={"host": "192.168.1.5:8000"}).status_code == 200)

    # A fake ngrok package records what start() asks for.
    calls = {}

    class Listener:
        def url(self):
            return "https://concrete-thank-kinetic.ngrok-free.dev"
    fake = types.ModuleType("ngrok")
    fake.forward = lambda addr, **opts: calls.update(addr=addr, **opts) or Listener()
    sys.modules["ngrok"] = fake
    try:
        try:
            tunnel.start(8085)
            check("missing NGROK_AUTHTOKEN is refused", False)
        except tunnel.TunnelError as e:
            check("missing NGROK_AUTHTOKEN is refused", "NGROK_AUTHTOKEN" in str(e), e)
        os.environ.update(NGROK_AUTHTOKEN="t0k3n", NGROK_DOMAIN="https://concrete-thank-kinetic.ngrok-free.dev/")
        url = tunnel.start(8085)
        check("tunnel forwards to the dashboard's own port", calls.get("addr") == "localhost:8085", calls)
        check("authtoken read from the environment, not passed in code",
              calls.get("authtoken_from_env") is True and "authtoken" not in calls, calls)
        check("fixed domain used, scheme and slash stripped",
              calls.get("domain") == "concrete-thank-kinetic.ngrok-free.dev", calls)
        check("public URL recorded", url == tunnel.public_url() == "https://concrete-thank-kinetic.ngrok-free.dev")
    finally:
        del sys.modules["ngrok"]

    status = client.get("/api/status").json()
    check("/api/status reports the public URL", status.get("public_url") == url, status.get("public_url"))
    for path in ("/", "/dashboard", "/api/repos", "/api/status", "/api/findings"):
        r = client.get(path, headers=public)
        check(f"{path} refused through the tunnel", r.status_code == 403, r.status_code)
    check("POST /api/repos refused through the tunnel",
          client.post("/api/repos", json={"url": "https://github.com/a/b"}, headers=public).status_code == 403)
    check("public host alone (no forwarded header) is refused too",
          client.get("/api/repos", headers={"host": public["host"]}).status_code == 403)
    check("dashboard still works on localhost", client.get("/api/repos").status_code == 200
          and client.get("/dashboard").status_code == 200)

    os.environ["GITHUB_WEBHOOK_SECRET"] = "topsecret"
    r = client.post("/webhook/github", content=b"{}", headers={**public, "X-GitHub-Event": "ping"})
    check("GitHub webhook reachable through the tunnel and still signature-checked",
          r.status_code == 401 and r.json()["detail"] == "Invalid webhook signature", r.text)
    import hashlib, hmac
    sig = "sha256=" + hmac.new(b"topsecret", b"{}", hashlib.sha256).hexdigest()
    r = client.post("/webhook/github", content=b"{}",
                    headers={**public, "X-GitHub-Event": "ping", "X-Hub-Signature-256": sig})
    check("signed ping through the tunnel succeeds", r.status_code == 200 and "reachable" in r.text, r.text)

    os.environ["NGROK_EXPOSE_DASHBOARD"] = "true"
    check("NGROK_EXPOSE_DASHBOARD=true opens the dashboard",
          client.get("/api/repos", headers=public).status_code == 200)
    os.environ.pop("NGROK_EXPOSE_DASHBOARD")

    # python -m app.serve: tunnel on the same port, then uvicorn; never needs the real ngrok.
    import uvicorn
    ran = {}
    real_run, real_start = uvicorn.run, tunnel.start
    uvicorn.run = lambda app, host, port: ran.update(host=host, port=port)
    tunnel.start = lambda port: ran.update(tunnel_port=port) or "https://x.ngrok-free.dev"
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = serve.main(["--port", "8085", "--ngrok"])
        check("serve --ngrok: tunnel and server on the same port, bound to localhost",
              code == 0 and ran == {"tunnel_port": 8085, "host": "127.0.0.1", "port": 8085}, ran)
        check("serve prints the webhook payload URL", "https://x.ngrok-free.dev/webhook/github" in out.getvalue())
        ran.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            serve.main(["--port", "8001"])
        check("serve without --ngrok opens no tunnel", "tunnel_port" not in ran and ran.get("port") == 8001, ran)
    finally:
        uvicorn.run, tunnel.start = real_run, real_start

    sys.modules["ngrok"] = None            # import ngrok -> ImportError
    try:
        tunnel.start(8000)
        check("missing ngrok package: clear message", False)
    except tunnel.TunnelError as e:
        check("missing ngrok package: clear message", "pip install ngrok" in str(e), e)
    finally:
        del sys.modules["ngrok"]
    for k in ("SENTINEL_PUBLIC_URL", "NGROK_AUTHTOKEN", "NGROK_DOMAIN", "GITHUB_WEBHOOK_SECRET"):
        os.environ.pop(k, None)


def main_all():
    smtp = FakeSMTP()
    smtp.start()
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
    # CI runners set these; they would point scans at the runner's commit
    # instead of the temporary repos built here.
    for k in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_SHA", "GITHUB_REPOSITORY", "GIT_COMMIT", "JOB_NAME"):
        os.environ.pop(k, None)
    test_email(smtp)
    test_cli(smtp)
    test_webhooks()
    test_tunnel()
    print(f"\n{'ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main_all())
