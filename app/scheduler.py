"""
Background polling — this is what makes the pipeline "continuous" rather
than just an on-demand scanner. Every POLL_INTERVAL_SECONDS, it runs an
incremental scan against every registered repo.

GitHub doesn't push events to a plain HTTP poller without a public
webhook endpoint, so polling the commits API is the simple, deploy-anywhere
approach; the /webhook/github route (app/main.py) gives push-based updates
on top. Each poll scans the new commits' code and, when the branch moved,
refreshes the git-history scan too (pipeline.scan_for_updates).
"""
import os
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

from . import db, pipeline

logger = logging.getLogger("secret-sentinel.scheduler")

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "300"))

_scheduler: BackgroundScheduler = None


def _poll_all_repos():
    for repo in db.list_repos():
        try:
            result = pipeline.scan_for_updates(repo["id"])
            logger.info("Polled %s/%s: %s", repo["owner"], repo["name"], result)
        except Exception:
            logger.exception("Poll failed for repo %s (%s/%s)", repo["id"], repo["owner"], repo["name"])


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        _poll_all_repos, "interval", seconds=POLL_INTERVAL_SECONDS, id="poll_all_repos",
        next_run_time=datetime.now() + timedelta(seconds=30),  # first poll shortly after startup
        max_instances=1, coalesce=True,
    )
    _scheduler.start()
    logger.info("Scheduler started, polling every %s seconds", POLL_INTERVAL_SECONDS)
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
