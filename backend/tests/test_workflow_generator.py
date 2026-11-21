import json
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.main import create_app
from backend.runner import plan_run
from backend.schemas import WorkflowDraft


class WorkflowGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.storage = Mock()
        self.model = Mock()
        for patcher in (
            patch.dict("os.environ", {"LLM_PROVIDER": "local", "LOCAL_LLM_MODEL": "generator-test",
                                      "DEEPSEEK_MODEL": "deepseek-flash", "DEEPSEEK_API_KEY": "synthetic-key"}),
            patch("backend.main.Storage", return_value=self.storage),
            patch("backend.main.client_for", return_value=self.model),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.client = TestClient(create_app("unused"))
        self.addCleanup(self.client.close)

    def generate(self, **extra):
        return self.client.post("/workflows/generate", json={
            "description": "Проверь учебный ZIP на секреты.", "timezone": "Europe/Moscow", **extra,
        })

    def test_daily_draft_has_an_explicit_branch_and_no_external_bindings(self):
        self.model.complete.return_value = json.dumps({
            "name": "Проверка учебного проекта",
            "scanners": ["secrets", "sca"],
            "explain": True,
            "condition": {"conditionMode": "severity", "minSeverity": "high"},
            "notification": "match",
            "scheduleTime": "14:00",
        })
        response = self.generate(description="Каждый день в 14:00 проверь секреты и зависимости, дай AI-рекомендации и отправь уведомление, если есть находки высокой критичности.")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertTrue(result["needsSource"])
        self.assertTrue(result["needsRecipient"])
        draft = WorkflowDraft.model_validate(result["draft"])
        self.assertEqual([n.type for n in draft.nodes], ["trigger", "secrets", "sca", "ai", "condition", "notify"])
        self.assertEqual(draft.nodes[0].config, {
            "mode": "daily", "scheduleTime": "14:00", "scheduleTimezone": "Europe/Moscow",
        })
        self.assertEqual(draft.nodes[-1].config, {})
        self.assertEqual(draft.edges[-1].source, draft.nodes[-2].id)
        self.assertEqual(draft.edges[-1].sourceHandle, "true")
        self.assertEqual(self.storage.mock_calls, [])
        self.assertEqual(self.model.complete.call_args.args[0][1], {
            "role": "user", "content": "Каждый день в 14:00 проверь секреты и зависимости, дай AI-рекомендации и отправь уведомление, если есть находки высокой критичности.",
        })
        draft.nodes[0].config["scheduleSourceId"] = "approved-source"
        draft.nodes[-1].config["webhookRef"] = "approved-receiver"
        plan_run(draft)

    def test_invalid_condition_is_retried_and_manual_draft_runs(self):
        self.model.complete.side_effect = [
            json.dumps({"name": "Draft", "scanners": ["secrets"],
                        "condition": {"conditionMode": "regex", "field": "file", "pattern": "(?=invalid)"}}),
            json.dumps({"name": "Draft", "scanners": ["secrets"], "explain": True}),
        ]
        response = self.generate(description="Проверь секреты и дай рекомендации по файлам, подходящим под регулярное выражение.")
        self.assertEqual(response.status_code, 200)
        plan_run(WorkflowDraft.model_validate(response.json()["draft"]))
        self.assertEqual(self.model.complete.call_count, 2)
        retry = self.model.complete.call_args.args[0][-1]["content"]
        self.assertIn("Ответ отклонён", retry)  # the model hears why, not a bare "fix it"
        self.assertNotEqual(retry.split(":", 1)[1].strip(), "")

    def test_untrusted_model_cannot_supply_a_webhook_url(self):
        self.model.complete.return_value = json.dumps({
            "name": "Draft", "scanners": ["secrets"], "notification": "always",
            "webhookUrl": "https://example.invalid/receiver",
        })
        response = self.generate()
        self.assertEqual((response.status_code, response.json()["code"]), (502, "invalid_response"))
        self.assertEqual(self.storage.mock_calls, [])

    def test_deepseek_requires_consent_for_generation(self):
        response = self.generate(modelId="deepseek:deepseek-flash")
        self.assertEqual((response.status_code, response.json()["code"]), (403, "consent_required"))
        self.model.complete.assert_not_called()

    def test_unsupported_requests_are_reported_without_a_retry(self):
        self.model.complete.return_value = '{"unsupported":true}'
        response = self.generate()
        self.assertEqual((response.status_code, response.json()["code"]), (422, "unsupported_generation"))
        self.model.complete.assert_called_once()

    def test_parts_the_user_did_not_ask_for_are_dropped(self):
        # real qwen3:8b answers: a conditional notification without a condition, every scanner, a foreign time zone
        cases = [
            ("каждый день в 10:00 статический анализ",
             {"name": "SAST", "scanners": ["sast"], "condition": None, "notification": "no_match", "scheduleTime": "10:00"},
             ["trigger", "sast"], False),
            ("Создай сценарий: каждый день в 10:00 SAST и уведомление",
             {"name": "SAST", "scanners": ["sast", "sca", "secrets"], "condition": {"conditionMode": "severity", "minSeverity": "high"},
              "notification": "match", "scheduleTime": "10:00", "scheduleTimezone": "America/Los_Angeles"},
             ["trigger", "sast", "notify"], True),
            ("проверь секреты",
             {"name": "Секреты", "scanners": ["secrets"], "explain": True, "notification": "always", "scheduleTime": "09:00"},
             ["trigger", "secrets"], False),
        ]
        for description, answer, types, notify in cases:
            with self.subTest(description=description):
                self.model.complete.reset_mock()
                self.model.complete.side_effect = None
                self.model.complete.return_value = json.dumps(answer)
                response = self.generate(description=description)
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()
                draft = WorkflowDraft.model_validate(result["draft"])
                self.assertEqual([n.type for n in draft.nodes], types)
                self.assertEqual(result["needsRecipient"], notify)
                self.model.complete.assert_called_once()
                trigger = draft.nodes[0].config
                if "10:00" in description:
                    self.assertEqual(trigger, {"mode": "daily", "scheduleTime": "10:00", "scheduleTimezone": "Europe/Moscow"})
                else:
                    self.assertEqual(trigger, {"mode": "manual"})

    def test_named_time_zone_and_time_come_from_the_description(self):
        self.model.complete.return_value = json.dumps({"name": "Daily", "scanners": ["secrets"], "scheduleTime": "08:00"})
        response = self.generate(description="Ежедневно в 7.30 по Asia/Tokyo ищи пароли")
        self.assertEqual(response.json()["draft"]["nodes"][0]["config"],
                         {"mode": "daily", "scheduleTime": "07:30", "scheduleTimezone": "Asia/Tokyo"})

    def test_scoped_description_creates_a_source_edge_for_each_scanner(self):
        self.model.complete.return_value = json.dumps({
            "name": "Draft", "scanners": ["secrets", "sast"], "scanPath": "src/main",
        })
        response = self.generate(description="Проверь секреты и SAST только в папке src/main учебного ZIP.")
        self.assertEqual(response.status_code, 200)
        draft = WorkflowDraft.model_validate(response.json()["draft"])
        source, = (node for node in draft.nodes if node.type == "source")
        self.assertEqual(source.config, {"path": "src/main"})
        scopes = [edge for edge in draft.edges if edge.targetHandle == "source"]
        self.assertEqual(len(scopes), 2)
        self.assertTrue(all(edge.source == source.id for edge in scopes))
        plan_run(draft)
