import json
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from backend import llm
from backend.llm import LlmClient, LlmError
from backend.llm_budget import BudgetExceeded, UsageBudget


class Clock:
    def __init__(self):
        self.now, self.day = 1000.0, date(2026, 11, 21)

    def __call__(self):
        return self.now

    def today(self):
        return self.day


LIMITS = {"DEEPSEEK_DAILY_REQUESTS": "3", "DEEPSEEK_DAILY_TOKENS": "1000", "DEEPSEEK_MINUTE_REQUESTS": "2"}


class UsageBudgetTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, LIMITS)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.clock = Clock()
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "usage.json"

    def budget(self):
        return UsageBudget(str(self.path), clock=self.clock, today=self.clock.today)

    def assert_blocked(self, budget, code):
        with self.assertRaises(BudgetExceeded) as error:
            budget.acquire()
        self.assertEqual(error.exception.code, code)

    def test_requests_per_minute_and_per_day(self):
        budget = self.budget()
        budget.acquire(); budget.acquire()
        self.assert_blocked(budget, "usage_limited")
        self.clock.now += 61
        budget.acquire()
        self.clock.now += 61
        self.assert_blocked(budget, "budget_exceeded")  # 3 requests a day
        self.assertEqual(budget.exhausted(), "budget_exceeded")

    def test_tokens_per_day_and_the_next_day_starts_clean(self):
        budget = self.budget()
        budget.acquire(); budget.record(1200)
        self.assert_blocked(budget, "budget_exceeded")
        self.clock.day = date(2026, 11, 22)
        self.assertIsNone(budget.exhausted())
        budget.acquire()

    def test_counters_survive_a_restart_on_the_same_day_only(self):
        budget = self.budget()
        budget.acquire(); budget.record(400)
        self.assertEqual(json.loads(self.path.read_text())["tokens"], 400)
        restarted = self.budget()
        self.assertEqual((restarted.requests, restarted.tokens), (1, 400))
        self.clock.day = date(2026, 11, 22)
        self.assertEqual(self.budget().requests, 0)

    def test_zero_turns_a_limit_off(self):
        with mock.patch.dict(os.environ, {"DEEPSEEK_MINUTE_REQUESTS": "0", "DEEPSEEK_DAILY_REQUESTS": "0"}):
            budget = self.budget()
            for _ in range(10):
                budget.acquire()


class Response:
    def __init__(self, usage):
        self.status_code, self.is_success, self.text = 200, True, "{}"
        self.usage = usage

    def json(self):
        body = {"choices": [{"finish_reason": "stop", "message": {"content": "ok"}}]}
        if self.usage is not None:
            body["usage"] = self.usage
        return body


class ClientBudgetTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        with mock.patch.dict(os.environ, LIMITS):
            self.budget = UsageBudget(None, clock=self.clock, today=self.clock.today)
        for patcher in (mock.patch.dict(os.environ, LIMITS), mock.patch.object(llm, "DEEPSEEK_BUDGET", self.budget)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, provider, usage=None):
        http = mock.MagicMock()
        http.__enter__.return_value.post.return_value = Response(usage)
        with mock.patch.object(llm.httpx, "Client", return_value=http):
            return LlmClient(provider, "https://example.invalid", "m", 5, "key").complete([{"role": "user", "content": "hi"}])

    def test_deepseek_requests_are_counted_and_stopped_at_the_limit(self):
        self.call("deepseek", {"total_tokens": 300})
        self.call("deepseek", {"prompt_tokens": 100, "completion_tokens": 50})
        self.assertEqual((self.budget.requests, self.budget.tokens), (2, 450))
        with self.assertRaises(LlmError) as error:
            self.call("deepseek")
        self.assertEqual(error.exception.code, "usage_limited")

    def test_missing_usage_is_estimated_and_local_models_are_free(self):
        self.call("deepseek", None)
        self.assertGreater(self.budget.tokens, 0)
        for _ in range(5):
            self.call("local")
        self.assertEqual(self.budget.requests, 1)

    def test_exhausted_budget_marks_deepseek_unavailable(self):
        self.budget.tokens = 5000
        with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": "key", "DEEPSEEK_MODEL": "deepseek-flash", "DEEPSEEK_MODELS": ""}), \
                mock.patch.object(llm, "_installed_local_models", return_value=[]):
            option = next(o for o in llm.list_model_options() if o.provider == "deepseek")
        self.assertEqual((option.available, option.reason), (False, "budget_exceeded"))


if __name__ == "__main__":
    unittest.main()
