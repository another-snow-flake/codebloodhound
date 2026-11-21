import asyncio
import logging
from datetime import datetime, timezone

from .runner import execute_plan, plan_run
from .storage import Storage


logger = logging.getLogger(__name__)
POLL_SECONDS = 10


def run_due_schedule(storage: Storage) -> bool:
    task = storage.claim_daily_run(datetime.now(timezone.utc))
    if task is None:
        return False
    workflow, report, source_id, archive = task
    try:
        execute_plan(storage, report, plan_run(workflow), source_id, archive)
    except Exception:
        logger.exception("Scheduled run %s did not complete", report.runId)
        report.status = "failed"
        for result in report.nodes:
            if result.status in ("running", "queued"):
                result.status = "failed" if result.status == "running" else "skipped"
                result.error = "The scheduled run did not complete."
        storage.save_run(report)
    return True


async def poll_schedules(storage: Storage) -> None:
    while True:
        try:
            if await asyncio.to_thread(run_due_schedule, storage):
                continue
        except Exception:
            logger.exception("Could not check for scheduled workflows")
        await asyncio.sleep(POLL_SECONDS)
