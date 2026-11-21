import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.accounts import Account
from backend.main import create_app
from backend.schemas import ApiProblem, Workflow
from backend.workflow_templates import TemplateMetadata, make_public_draft


def saved_workflow(plugins=None):
    specs = [
        ("start", "trigger", {"mode": "daily", "scheduleTime": "14:00", "scheduleTimezone": "UTC",
                              "scheduleSourceId": "private-archive", "scheduleSourceName": "Private ZIP"}),
        ("scan", "sast", {"note": "Private note"}),
        ("where", "source", {"path": "src/main"}),
        ("notify", "notify", {"webhookRef": "private-receiver", "extra": "not public"}),
    ]
    return Workflow.model_validate({
        "id": "personal", "name": "Private workflow title", "languagePlugins": plugins,
        "nodes": [{"id": key, "type": kind, "config": config, "position": {"x": 0, "y": 0}}
                  for key, kind, config in specs],
        "edges": [
            {"id": "start-scan", "source": "start", "target": "scan"},
            {"id": "scope", "source": "where", "target": "scan", "targetHandle": "source"},
            {"id": "scan-notify", "source": "scan", "target": "notify"},
        ],
    })


class PublicWorkflowDraftTest(unittest.TestCase):
    def test_portable_copy_preserves_graph_and_omits_private_bindings(self):
        workflow = saved_workflow(["python"])
        draft = make_public_draft(workflow, "Public example")
        self.assertEqual(draft.name, "Public example")
        self.assertEqual(draft.edges, workflow.edges)
        self.assertEqual(draft.nodes[0].config, {"mode": "daily", "scheduleTime": "14:00", "scheduleTimezone": "UTC"})
        self.assertEqual(draft.nodes[1].config, {})
        self.assertEqual(draft.nodes[2].config, {"path": "src/main"})
        self.assertEqual(draft.nodes[3].config, {})
        self.assertNotIn("languagePlugins", draft.model_dump())
        self.assertEqual(workflow.nodes[0].config["scheduleSourceId"], "private-archive")

    def test_tags_are_trimmed_and_distinct_in_input_order(self):
        metadata = TemplateMetadata(title="Public", description="Details", tags=["Kotlin ", "SCA", "kotlin"])
        self.assertEqual(metadata.tags, ["Kotlin", "SCA"])

    def test_public_copy_preserves_custom_scanner_and_source_connection(self):
        workflow = saved_workflow()
        scanner = workflow.nodes[1]
        scanner.type = "custom"
        scanner.config = {"title": "Custom scan", "color": "#2f6b4f", "inputs": 1, "outputs": 1,
                          "scanner": "sast", "language": "python", "note": "Private note"}
        draft = make_public_draft(workflow, "Public example")
        self.assertEqual(draft.nodes[1].config, {key: value for key, value in scanner.config.items() if key != "note"})
        self.assertEqual(draft.edges[1].targetHandle, "source")

    def test_workflow_with_a_private_plugin_cannot_be_published(self):
        workflow = saved_workflow()
        workflow.nodes[1].config["privatePluginOwner"] = "owner-id"
        with self.assertRaises(ApiProblem) as raised:
            make_public_draft(workflow, "Public example")
        self.assertEqual(raised.exception.code, "private_plugin_in_workflow")


class PublishWorkflowTest(unittest.TestCase):
    def test_only_an_authenticated_owner_can_publish(self):
        storage = Mock()
        storage.session_account.return_value = Account(id="owner", username="owner", languagePlugins=[])
        storage.get_workflow.return_value = saved_workflow()
        with patch("backend.main.Storage", return_value=storage):
            client = TestClient(create_app("unused"))
        self.addCleanup(client.close)
        meta = {"title": "Public", "description": "Example", "workflowId": "personal"}
        self.assertEqual(client.put("/workflow-templates", json=meta).status_code, 401)
        response = client.put("/workflow-templates", json=meta, headers={"X-CodeBloodhound-Session": "a" * 43})
        self.assertEqual(response.status_code, 403)
        storage.get_workflow.assert_called_once_with("personal", owner_id="owner")
        storage.publish_workflow_template.assert_not_called()
