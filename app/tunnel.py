"""
Optional public tunnel (ngrok), so GitHub can reach a dashboard running on a
laptop: the push webhook (/webhook/github) and the CI notification
(/webhook/ci). Started by `python -m app.serve --ngrok`; plain
`uvicorn app.main:app` never opens one.

Settings (.env):
    NGROK_AUTHTOKEN          your ngrok authtoken (read by the ngrok package)
    NGROK_DOMAIN             optional fixed domain, e.g. you.ngrok-free.dev
    NGROK_EXPOSE_DASHBOARD   true = the whole dashboard is public (default: false)

The dashboard has no login, so by default the tunnel carries ONLY the two
webhook routes, which authenticate themselves (HMAC signature / token). The
pages and the API answer 403 to anything that came through the tunnel and stay
usable at http://localhost:<port> as before. Needs `pip install ngrok`.
"""
import os
from typing import Any, Optional

PUBLIC_PATH_PREFIXES = ("/webhook/",)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

_listener: Any = None        # keep a reference: the tunnel closes when it is garbage-collected


class TunnelError(RuntimeError):
    pass


def public_url() -> Optional[str]:
    """The tunnel's public base URL while one is open (set by start())."""
    return os.environ.get("SENTINEL_PUBLIC_URL") or None


def dashboard_exposed() -> bool:
    return os.environ.get("NGROK_EXPOSE_DASHBOARD", "false").strip().lower() == "true"


def start(port: int) -> str:
    """Open the tunnel to localhost:<port> and return its public URL."""
    global _listener
    try:
        import ngrok
    except ImportError as e:
        raise TunnelError("The ngrok package is not installed. Run: pip install ngrok") from e
    if not os.environ.get("NGROK_AUTHTOKEN", "").strip():
        raise TunnelError("NGROK_AUTHTOKEN is not set. Add it to .env "
                          "(dashboard.ngrok.com -> Your Authtoken).")
    options: dict = {"authtoken_from_env": True}
    domain = os.environ.get("NGROK_DOMAIN", "").strip()
    if domain:
        options["domain"] = domain.removeprefix("https://").rstrip("/")
    try:
        _listener = ngrok.forward(f"localhost:{port}", **options)
    except Exception as e:  # the SDK raises its own error types
        raise TunnelError(f"ngrok could not open the tunnel: {e}") from e
    url = _listener.url().rstrip("/")
    os.environ["SENTINEL_PUBLIC_URL"] = url
    return url


def came_through_tunnel(host_header: str, forwarded_for: Optional[str]) -> bool:
    """True for a request that reached us through the tunnel rather than from
    this machine. ngrok adds X-Forwarded-For and keeps its public host name;
    a local browser sends neither."""
    if forwarded_for:
        return True
    host = (host_header or "").lower()
    host = host[:host.find("]") + 1] if host.startswith("[") else host.split(":")[0]   # drop the port
    return host not in LOCAL_HOSTS


def blocks(path: str, host_header: str, forwarded_for: Optional[str]) -> bool:
    """Whether the dashboard must refuse this request (only while a tunnel is open)."""
    if not public_url() or dashboard_exposed():
        return False
    if path.startswith(PUBLIC_PATH_PREFIXES):
        return False
    return came_through_tunnel(host_header, forwarded_for)
