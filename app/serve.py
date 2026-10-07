"""
Run the dashboard, optionally with a public ngrok tunnel for GitHub webhooks.

    python -m app.serve                  # same as: uvicorn app.main:app --port 8000
    python -m app.serve --port 8085
    python -m app.serve --ngrok          # also open the tunnel (settings: app/tunnel.py)

With --ngrok it prints the two addresses to give GitHub. The dashboard itself
stays at http://localhost:<port>; only the webhook routes are public unless
NGROK_EXPOSE_DASHBOARD=true.
"""
import argparse
import os
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.serve", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    ap.add_argument("--host", default="127.0.0.1",
                    help="interface to listen on (default: this machine only)")
    ap.add_argument("--ngrok", action="store_true",
                    default=os.environ.get("NGROK_ENABLED", "false").strip().lower() == "true",
                    help="open a public ngrok tunnel for GitHub webhooks (or NGROK_ENABLED=true)")
    args = ap.parse_args(argv)

    from . import main as app_main     # loads .env first, so NGROK_* settings from .env apply
    from . import tunnel

    if args.ngrok:
        try:
            url = tunnel.start(args.port)
        except tunnel.TunnelError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        exposed = tunnel.dashboard_exposed()
        print(f"""
ngrok tunnel open: {url}
  GitHub push webhook (repo Settings -> Webhooks -> Payload URL):
      {url}/webhook/github      (Secret field: your GITHUB_WEBHOOK_SECRET value from .env)
  CI notification (repo variable SENTINEL_URL):
      {url}                     (repo secret SENTINEL_TOKEN: the same value as in .env)
  Dashboard: http://localhost:{args.port}/dashboard"""
              + ("   (ALSO PUBLIC: NGROK_EXPOSE_DASHBOARD=true, and it has no login)" if exposed
                 else "   (local only; the tunnel carries the webhooks alone)") + "\n")
        for name in ("GITHUB_WEBHOOK_SECRET", "SENTINEL_TOKEN"):
            if not os.environ.get(name, "").strip():
                print(f"warning: {name} is not set, so its webhook accepts unauthenticated calls.",
                      file=sys.stderr)

    import uvicorn
    uvicorn.run(app_main.app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
