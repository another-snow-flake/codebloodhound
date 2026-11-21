"""Spending limits for the paid model provider (DeepSeek).

The demo site is open to anyone with the invite link, so the server caps DeepSeek use:
requests per day, tokens per day and requests per minute. Counters for the day survive
restarts when LLM_USAGE_FILE points to a writable file. The limits come from:

    DEEPSEEK_DAILY_REQUESTS   (default 300)
    DEEPSEEK_DAILY_TOKENS     (default 1500000, prompt and answer tokens together)
    DEEPSEEK_MINUTE_REQUESTS  (default 20)

Zero or a negative number turns that limit off.
"""

import json
import os
import threading
import time
from collections import deque
from datetime import date
from pathlib import Path

DEFAULTS = {"DEEPSEEK_DAILY_REQUESTS": 300, "DEEPSEEK_DAILY_TOKENS": 1_500_000, "DEEPSEEK_MINUTE_REQUESTS": 20}


class BudgetExceeded(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _limit(name: str) -> int:
    try:
        return int(os.getenv(name, str(DEFAULTS[name])))
    except ValueError:
        return DEFAULTS[name]


class UsageBudget:
    def __init__(self, path: str | None = None, clock=time.monotonic, today=date.today):
        self.path = Path(path) if path else None
        self.clock, self.today = clock, today
        self.lock = threading.Lock()
        self.minute: deque[float] = deque()
        self.day, self.requests, self.tokens = self.today().isoformat(), 0, 0
        self._load()

    def _load(self):
        if not self.path:
            return
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if saved.get("day") == self.day:
                self.requests, self.tokens = int(saved.get("requests", 0)), int(saved.get("tokens", 0))
        except (OSError, ValueError, TypeError, AttributeError):
            pass

    def _save(self):
        if not self.path:
            return
        try:
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"day": self.day, "requests": self.requests, "tokens": self.tokens}), encoding="utf-8")
            temporary.replace(self.path)
        except OSError:
            pass  # the limits still hold in memory

    def _roll(self):
        day = self.today().isoformat()
        if day != self.day:
            self.day, self.requests, self.tokens = day, 0, 0

    def exhausted(self) -> str | None:
        """The daily limit that is used up, or None."""
        with self.lock:
            self._roll()
            requests, tokens = _limit("DEEPSEEK_DAILY_REQUESTS"), _limit("DEEPSEEK_DAILY_TOKENS")
            if requests > 0 and self.requests >= requests or tokens > 0 and self.tokens >= tokens:
                return "budget_exceeded"
            return None

    def acquire(self):
        """Count one request before it is sent, or raise BudgetExceeded."""
        with self.lock:
            self._roll()
            requests, tokens = _limit("DEEPSEEK_DAILY_REQUESTS"), _limit("DEEPSEEK_DAILY_TOKENS")
            if requests > 0 and self.requests >= requests or tokens > 0 and self.tokens >= tokens:
                raise BudgetExceeded("budget_exceeded", "The daily DeepSeek limit of this server is used up.")
            per_minute, now = _limit("DEEPSEEK_MINUTE_REQUESTS"), self.clock()
            while self.minute and now - self.minute[0] >= 60:
                self.minute.popleft()
            if per_minute > 0 and len(self.minute) >= per_minute:
                raise BudgetExceeded("usage_limited", "Too many DeepSeek requests this minute. Try again shortly.")
            self.minute.append(now)
            self.requests += 1
            self._save()

    def record(self, tokens: int):
        with self.lock:
            self._roll()
            self.tokens += max(0, int(tokens))
            self._save()

    def snapshot(self) -> dict:
        with self.lock:
            self._roll()
            return {"day": self.day, "requests": self.requests, "tokens": self.tokens,
                    "requestLimit": _limit("DEEPSEEK_DAILY_REQUESTS"), "tokenLimit": _limit("DEEPSEEK_DAILY_TOKENS")}


DEEPSEEK_BUDGET = UsageBudget(os.getenv("LLM_USAGE_FILE") or None)
