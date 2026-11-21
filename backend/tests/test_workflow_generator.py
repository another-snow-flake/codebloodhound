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
        response = self.generate()
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
            "role": "user", "content": "Проверь учебный ZIP на секреты.",
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
        response = self.generate()
        self.assertEqual(response.status_code, 200)
        plan_run(WorkflowDraft.model_validate(response.json()["draft"]))
        self.assertEqual(self.model.complete.call_count, 2)

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
