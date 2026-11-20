import os
import threading
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from backend import llm
from backend.llm import LlmError, ModelSpec, check_model, default_model_id, list_model_options, load_llm, resolve_model
from backend.main import create_app
from backend.runner import execute_plan, plan_run
from backend.schemas import NodeResult, RunReport, WorkflowDraft


ENV = {
    "LLM_PROVIDER": "local",
    "LOCAL_LLM_MODEL": "qwen3:8b",
    "LOCAL_LLM_MODELS": "",
    "DEEPSEEK_API_KEY": "test-key",
    "DEEPSEEK_MODEL": "deepseek-flash",
    "DEEPSEEK_MODELS": "",
}


class FakeStorage:
    def __init__(self):
        self.runs, self.sources = {}, {}

    def save_source(self, source_id, archive):
        self.sources[source_id] = archive

    def get_source(self, source_id):
        return self.sources.get(source_id)

    def get_workflow(self, workflow_id):
        return self.workflow

    def save_run(self, report):
        self.runs[report.runId] = report.model_copy(deep=True)

    def get_run(self, run_id):
        return self.runs.get(run_id)


def workflow(with_ai=True):
    nodes = [{"id": "t", "type": "trigger", "position": {"x": 0, "y": 0}},
             {"id": "s", "type": "secrets", "position": {"x": 1, "y": 0}}]
    edges = [{"id": "e1", "source": "t", "target": "s"}]
    if with_ai:
        nodes.append({"id": "a", "type": "ai", "position": {"x": 2, "y": 0}})
        edges.append({"id": "e2", "source": "s", "target": "a"})
    from backend.schemas import Workflow
    return Workflow(id="w", name="W", nodes=nodes, edges=edges)


class ModelSettingsTest(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)

    def installed(self, *models):
        return mock.patch.object(llm, "_installed_local_models", return_value=list(models))

    def test_lists_installed_local_models_and_deepseek(self):
        with self.installed("qwen3:4b-instruct", "qwen3:8b"):
            options = {option.id: option for option in list_model_options()}
        self.assertEqual(list(options), ["local:qwen3:4b-instruct", "local:qwen3:8b", "deepseek:deepseek-flash"])

    def test_configured_model_that_is_not_installed_is_marked(self):
        with mock.patch.dict(os.environ, {"LOCAL_LLM_MODELS": "qwen3:14b"}), self.installed("qwen3:8b"):
            options = {option.id: option for option in list_model_options()}
        self.assertEqual(options["local:qwen3:14b"].reason, "model_missing")

    def test_unreachable_local_server_keeps_configured_models(self):
        with mock.patch.object(llm, "_installed_local_models", side_effect=LlmError("connection_error", "down")):
            options = list_model_options()
        self.assertEqual((options[0].id, options[0].reason), ("local:qwen3:8b", "connection_error"))

    def test_no_id_means_the_server_environment(self):
        self.assertEqual(default_model_id(), "local:qwen3:8b")
        self.assertEqual(resolve_model(None), ModelSpec("local", "qwen3:8b"))
        with mock.patch.dict(os.environ, {"LLM_PROVIDER": ""}), self.assertRaises(LlmError) as error:
            resolve_model(None)
        self.assertEqual(error.exception.code, "not_configured")

    def test_deepseek_needs_consent_and_a_key(self):
        with self.assertRaises(LlmError) as error:
            resolve_model("deepseek:deepseek-flash")
        self.assertEqual(error.exception.code, "consent_required")
        self.assertEqual(resolve_model("deepseek:deepseek-flash", allow_external=True).provider, "deepseek")
        with mock.patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), self.assertRaises(LlmError) as error:
            resolve_model("deepseek:deepseek-flash", allow_external=True)
        self.assertEqual(error.exception.code, "no_api_key")

    def test_unknown_or_malformed_models_are_rejected(self):
        for model_id in ("deepseek:other", "openai:gpt", "local:", "local:../../x y"):
            with self.subTest(model_id=model_id), self.assertRaises(LlmError) as error:
                resolve_model(model_id, allow_external=True)
            self.assertEqual(error.exception.code, "unknown_model")

    def test_check_tells_failures_apart(self):
        for status, code in ((401, "auth_error"), (404, "model_missing"), (503, "upstream_error")):
            response = mock.Mock(is_success=False, status_code=status)
            client = mock.MagicMock()
            client.__enter__.return_value.post.return_value = response
            with self.subTest(status=status), mock.patch.object(llm.httpx, "Client", return_value=client), \
                    self.assertRaises(LlmError) as error:
                check_model(ModelSpec("local", "qwen3:8b"))
            self.assertEqual(error.exception.code, code)

    def test_check_accepts_a_cut_off_answer(self):
        with mock.patch.object(llm.LlmClient, "complete", side_effect=LlmError("incomplete_response", "cut")):
            self.assertGreaterEqual(check_model(ModelSpec("local", "qwen3:8b")), 0)


class PerRequestModelTest(unittest.TestCase):
    """Two tabs with different providers must not affect each other's runs or answers."""

    def setUp(self):
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.storage = FakeStorage()
        self.storage.workflow = workflow()
        self.storage.save_source("src", b"zip")
        storage_patch = mock.patch("backend.main.Storage", return_value=self.storage)
        storage_patch.start()
        self.addCleanup(storage_patch.stop)
        self.client = TestClient(create_app("unused"))
        self.started = []
        run_patch = mock.patch("backend.main.execute_plan", side_effect=lambda *args: self.started.append(args[-1]))
        run_patch.start()
        self.addCleanup(run_patch.stop)
        validate_patch = mock.patch("backend.main.validate_zip")
        validate_patch.start()
        self.addCleanup(validate_patch.stop)

    def run_with(self, **choice):
        return self.client.post("/workflows/w/runs", json={"sourceId": "src", **choice})

    def test_each_run_pins_its_own_model(self):
        self.assertEqual(self.run_with(modelId="local:qwen3:4b-instruct").status_code, 202)
        self.assertEqual(self.run_with(modelId="deepseek:deepseek-flash", allowExternal=True).status_code, 202)
        self.assertEqual(self.run_with().status_code, 202)
        self.assertEqual([spec.id for spec in self.started],
                         ["local:qwen3:4b-instruct", "deepseek:deepseek-flash", "local:qwen3:8b"])

    def test_deepseek_without_consent_is_refused_by_the_server(self):
        response = self.run_with(modelId="deepseek:deepseek-flash")
        self.assertEqual((response.status_code, response.json()["code"]), (403, "consent_required"))
        self.assertEqual(self.started, [])

    def test_run_without_ai_node_ignores_model_settings(self):
        self.storage.workflow = workflow(with_ai=False)
        with mock.patch.dict(os.environ, {"LLM_PROVIDER": ""}):
            self.assertEqual(self.run_with().status_code, 202)
        self.assertEqual(self.started, [None])

    def test_unconfigured_server_still_runs_scanners(self):
        with mock.patch.dict(os.environ, {"LLM_PROVIDER": ""}):
            self.assertEqual(self.run_with().status_code, 202)
        self.assertEqual(self.started, [None])

    def test_chat_uses_the_model_named_in_the_request(self):
        self.storage.save_run(RunReport(runId="r", workflowId="w", status="succeeded", nodes=[]))
        seen = []

        def fake_client(spec):
            seen.append(spec.id)
            return mock.Mock(complete=mock.Mock(return_value="Ответ."))

        with mock.patch("backend.main.client_for", side_effect=fake_client):
            local = self.client.post("/runs/r/chat", json={"question": "Что делать?", "modelId": "local:qwen3:4b-instruct"})
            remote = self.client.post("/runs/r/chat", json={
                "question": "Что делать?", "modelId": "deepseek:deepseek-flash", "allowExternal": True})
            refused = self.client.post("/runs/r/chat", json={"question": "Что делать?", "modelId": "deepseek:deepseek-flash"})
        self.assertEqual([local.json()["model"], remote.json()["model"]], seen)
        self.assertEqual(refused.status_code, 403)

    def test_settings_never_expose_keys_and_check_reports_reasons(self):
        with mock.patch.object(llm, "_installed_local_models", return_value=["qwen3:8b"]):
            settings = self.client.get("/settings/llm")
        self.assertEqual(settings.json()["defaultId"], "local:qwen3:8b")
        self.assertNotIn("test-key", settings.text)
        with mock.patch("backend.main.check_model", side_effect=LlmError("connection_error", "down")):
            down = self.client.post("/settings/llm/check", json={"modelId": "local:qwen3:8b"}).json()
        with mock.patch("backend.main.check_model", return_value=0.42):
            up = self.client.post("/settings/llm/check", json={"modelId": "local:qwen3:8b"}).json()
        refused = self.client.post("/settings/llm/check", json={"modelId": "deepseek:deepseek-flash"})
        self.assertEqual((down["ok"], down["code"]), (False, "connection_error"))
        self.assertEqual((up["ok"], up["seconds"]), (True, 0.42))
        self.assertEqual(refused.status_code, 403)


class PinnedModelInRunnerTest(unittest.TestCase):
    def test_ai_node_uses_the_model_pinned_at_start(self):
        import io
        import zipfile
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as content:
            content.writestr("application.properties", "db.password=synthetic\n")
        draft = WorkflowDraft.model_validate(workflow().model_dump())
        report = RunReport(runId="r", workflowId="w", nodes=[NodeResult(nodeId=n.id) for n in draft.nodes])
        used = []

        def fake_client(spec):
            used.append(spec.id)
            raise LlmError("connection_error", "down")

        with mock.patch("backend.runner.client_for", side_effect=fake_client), \
                mock.patch("backend.runner.load_llm", side_effect=AssertionError("environment model must not be used")):
            execute_plan(mock.Mock(), report, plan_run(draft), "src", archive.getvalue(), ModelSpec("local", "qwen3:4b-instruct"))
        self.assertEqual(used, ["local:qwen3:4b-instruct"])
        self.assertEqual(report.nodes[-1].output["errorCode"], "connection_error")


if __name__ == "__main__":
    unittest.main()
