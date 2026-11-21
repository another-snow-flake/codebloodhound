import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .schemas import ApiProblem, WorkflowDraft


DAILY_TIME = re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]")


@dataclass(frozen=True)
class DailySchedule:
    source_id: str
    wall_time: str
    zone: ZoneInfo

    def next_after(self, now: datetime) -> datetime:
        """Return the next wall-clock slot as UTC, at most once per local date."""
        local_day = now.astimezone(self.zone).date()
        clock = time.fromisoformat(self.wall_time)
        today = datetime.combine(local_day, clock, self.zone).astimezone(timezone.utc)
        if today > now:
            return today
        return datetime.combine(local_day + timedelta(days=1), clock, self.zone).astimezone(timezone.utc)


def daily_schedule(workflow: WorkflowDraft) -> DailySchedule | None:
    for node in workflow.nodes:
        config = node.config
        if node.type != "trigger" or config.get("mode") != "daily":
            continue
        source_id, wall_time, zone = (config.get(key) for key in ("scheduleSourceId", "scheduleTime", "scheduleTimezone"))
        if not isinstance(source_id, str) or not 1 <= len(source_id) <= 100:
            raise ApiProblem(422, "schedule_source_required", "Choose an uploaded project for the daily schedule.")
        if not isinstance(wall_time, str) or not DAILY_TIME.fullmatch(wall_time):
            raise ApiProblem(422, "invalid_schedule", "Enter the daily execution time as HH:MM.")
        if not isinstance(zone, str) or not 1 <= len(zone) <= 100:
            raise ApiProblem(422, "invalid_schedule", "Enter a valid IANA time zone.")
        try:
            return DailySchedule(source_id, wall_time, ZoneInfo(zone))
        except (ZoneInfoNotFoundError, ValueError):
            raise ApiProblem(422, "invalid_schedule", "Enter a valid IANA time zone.") from None
    return None
