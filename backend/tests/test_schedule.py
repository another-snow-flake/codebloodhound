import unittest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from backend.schedule import DailySchedule, daily_schedule
from backend.schemas import ApiProblem, RunReport, Workflow


class DailyScheduleTest(unittest.TestCase):
    def test_next_run_respects_timezone_and_moves_to_tomorrow_at_the_slot(self):
        schedule = DailySchedule("archive", "14:00", ZoneInfo("Europe/Moscow"))
        before = datetime(2026, 11, 21, 10, 59, tzinfo=timezone.utc)
        today = datetime(2026, 11, 21, 11, tzinfo=timezone.utc)
        self.assertEqual(schedule.next_after(before), today)
        self.assertEqual(schedule.next_after(today), datetime(2026, 11, 22, 11, tzinfo=timezone.utc))

    def test_ambiguous_hour_is_scheduled_once_per_local_day(self):
        schedule = DailySchedule("archive", "02:30", ZoneInfo("Europe/Berlin"))
        first = datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
        self.assertEqual(schedule.next_after(first), datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc))

    def test_rejects_invalid_source_time_and_timezone(self):
        base = {"mode": "daily", "scheduleSourceId": "archive", "scheduleTime": "14:00", "scheduleTimezone": "UTC"}
        for key, value, code in (
            ("scheduleSourceId", "", "schedule_source_required"),
            ("scheduleTime", "25:00", "invalid_schedule"),
            ("scheduleTimezone", "../UTC", "invalid_schedule"),
        ):
            with self.subTest(key=key), self.assertRaises(ApiProblem) as problem:
                daily_schedule(self.workflow(base | {key: value}))
            self.assertEqual(problem.exception.code, code)

    def test_queued_report_preserves_status_and_scheduled_time_when_serialized(self):
        slot = datetime(2026, 11, 21, 11, tzinfo=timezone.utc)
        body = RunReport.for_workflow(self.workflow({}), slot).model_dump(mode="json", exclude_unset=True)
        self.assertEqual(body["status"], "queued")
        self.assertEqual(body["nodes"][0]["status"], "queued")
        self.assertEqual(body["triggerMode"], "daily")
        self.assertEqual(body["scheduledFor"], "2026-11-21T11:00:00Z")

    def workflow(self, config):
        return Workflow.model_validate({
            "id": "workflow", "name": "Daily check", "edges": [],
            "nodes": [{"id": "t", "type": "trigger", "position": {"x": 0, "y": 0}, "config": config}],
        })
