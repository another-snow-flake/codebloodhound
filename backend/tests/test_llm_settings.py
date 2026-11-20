import os
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from backend import llm
from backend.llm import LlmError, list_model_options, load_llm, reset_model_selection, select_model, selected_model_id
from backend.main import create_app


ENV = {
    "LLM_PROVIDER": "local",
    "LOCAL_LLM_MODEL": "qwen3:8b",
    "LOCAL_LLM_MODELS": "",
    "DEEPSEEK_API_KEY": "test-key",
    "DEEPSEEK_MODEL": "deepseek-flash",
    "DEEPSEEK_MODELS": "",
}


class ModelSelectionTest(unittest.TestCase):
    def setUp(self):
        reset_model_selection()
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(reset_model_selection)

    def installed(self, *models):
        return mock.patch.object(llm, "_installed_local_models", return_value=list(models))

    def test_lists_installed_local_models_and_deepseek(self):
        with self.installed("qwen3:4b", "qwen3:8b"):
            options = {option.id: option for option in list_model_options()}
        self.assertEqual(list(options), ["local:qwen3:4b", "local:qwen3:8b", "deepseek:deepseek-flash"])
        self.assertTrue(all(option.available for option in options.values()))

    def test_configured_model_that_is_not_installed_is_marked(self):
        with mock.patch.dict(os.environ, {"LOCAL_LLM_MODELS": "qwen3:14b"}), self.installed("qwen3:8b"):
            options = {option.id: option for option in list_model_options()}
        self.assertEqual(options["local:qwen3:14b"].reason, "model_missing")

    def test_unreachable_local_server_keeps_configured_models(self):
        down = LlmError("connection_error", "down")
        with mock.patch.object(llm, "_installed_local_models", side_effect=down):
            options = list_model_options()
        self.assertEqual((options[0].id, options[0].available, options[0].reason),
                         ("local:qwen3:8b", False, "connection_error"))

    def test_deepseek_without_key_cannot_be_selected(self):
        with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), self.installed("qwen3:8b"):
            options = list_model_options()
            self.assertEqual(options[-1].reason, "no_api_key")
            with self.assertRaises(LlmError) as error:
                select_model("deepseek:deepseek-flash", options)
        self.assertEqual(error.exception.code, "no_api_key")

    def test_switch_applies_to_next_client_only(self):
        with self.installed("qwen3:4b", "qwen3:8b"):
            in_flight = load_llm()
            select_model("deepseek:deepseek-flash", list_model_options())
            self.assertEqual((load_llm().provider, load_llm().model), ("deepseek", "deepseek-flash"))
            select_model("local:qwen3:4b", list_model_options())
            self.assertEqual((load_llm().provider, load_llm().model), ("local", "qwen3:4b"))
        self.assertEqual((in_flight.provider, in_flight.model), ("local", "qwen3:8b"))

    def test_environment_decides_until_the_editor_selects(self):
        self.assertEqual(selected_model_id(), "local:qwen3:8b")
        with mock.patch.dict(os.environ, {"LLM_PROVIDER": ""}):
            self.assertIsNone(selected_model_id())
            with self.assertRaises(LlmError):
                load_llm()

    def test_unknown_model_is_rejected(self):
        with self.installed("qwen3:8b"), self.assertRaises(LlmError) as error:
            select_model("local:evil", list_model_options())
        self.assertEqual(error.exception.code, "unknown_model")

    def test_api_switches_without_restart_and_never_exposes_keys(self):
        client = TestClient(create_app("postgresql://unused"))
        with self.installed("qwen3:4b", "qwen3:8b"):
            current = client.get("/settings/llm").json()
            self.assertEqual(current["selectedId"], "local:qwen3:8b")
            switched = client.put("/settings/llm", json={"modelId": "deepseek:deepseek-flash"})
            self.assertEqual(switched.json()["selectedId"], "deepseek:deepseek-flash")
            back = client.put("/settings/llm", json={"modelId": "local:qwen3:8b"}).json()
            missing = client.put("/settings/llm", json={"modelId": "local:nope"})
        self.assertEqual(back["selectedId"], "local:qwen3:8b")
        self.assertEqual((missing.status_code, missing.json()["code"]), (404, "unknown_model"))
        self.assertNotIn("test-key", str(current) + switched.text)


    def test_missing_model_on_provider_has_its_own_code(self):
        response = mock.Mock(is_success=False, status_code=404)
        client = mock.MagicMock()
        client.__enter__.return_value.post.return_value = response
        with mock.patch.object(llm.httpx, "Client", return_value=client), self.assertRaises(LlmError) as error:
            load_llm().complete([{"role": "user", "content": "hi"}])
        self.assertEqual(error.exception.code, "model_missing")


if __name__ == "__main__":
    unittest.main()
