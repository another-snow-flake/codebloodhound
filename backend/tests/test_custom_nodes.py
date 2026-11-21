import io
import unittest
from unittest import mock
from unittest.mock import Mock
from zipfile import ZipFile

from fastapi.testclient import TestClient

from backend.main import create_app
from backend.runner import execute_plan, plan_run, validate_edges
from backend.schemas import ApiProblem, NodeResult, RunReport, WorkflowDraft


def custom(node_id, inputs=1, outputs=1, **extra):
    config = {"title": "Ручная проверка", "color": "#aa3355", "inputs": inputs, "outputs": outputs, **extra}
    return {"id": node_id, "type": "custom", "position": {"x": 1, "y": 1}, "config": config}


def node(node_id, kind, **config):
    return {"id": node_id, "type": kind, "position": {"x": 0, "y": 0}, "config": config}


def edge(source, target, out=None, into=None):
    item = {"id": f"{source}-{target}-{out}-{into}", "source": source, "target": target}
    if out:
        item["sourceHandle"] = out
    if into:
        item["targetHandle"] = into
    return item


def draft(nodes, edges):
    return WorkflowDraft.model_validate({"name": "Custom", "nodes": nodes, "edges": edges})


class CustomNodeValidationTest(unittest.TestCase):
    def assert_rejected(self, nodes, edges, code):
        with self.assertRaises(ApiProblem) as context:
            validate_edges(draft(nodes, edges))
        self.assertEqual(context.exception.code, code)

    def test_ports_must_match_the_node(self):
        nodes = [node("t", "trigger"), custom("c", inputs=2, outputs=2), node("s", "secrets")]
        validate_edges(draft(nodes, [edge("t", "c", into="in2"), edge("c", "s", out="out1")]))
        self.assert_rejected(nodes, [edge("c", "s")], "invalid_workflow")  # two outputs: the port must be named
        self.assert_rejected(nodes, [edge("c", "s", out="out3")], "invalid_workflow")
        self.assert_rejected(nodes, [edge("t", "c")], "invalid_workflow")  # two inputs: the port must be named
        self.assert_rejected(nodes, [edge("t", "s", into="in1")], "invalid_workflow")  # standard nodes have one input

    def test_single_ports_stay_unnamed_and_no_outputs_means_no_edges(self):
        nodes = [node("t", "trigger"), custom("c"), custom("end", outputs=0), node("s", "secrets")]
        validate_edges(draft(nodes, [edge("t", "c"), edge("c", "end")]))
        self.assert_rejected(nodes, [edge("end", "s")], "invalid_workflow")

    def test_config_is_checked(self):
        for bad in ({"color": "red"}, {"inputs": 0}, {"inputs": 5}, {"outputs": -1}, {"title": ""}, {"inputs": True}):
            nodes = [custom("c", **{key: value for key, value in custom("c")["config"].items()} | bad)]
            nodes[0]["config"].update(bad)
            self.assert_rejected(nodes, [], "invalid_node_config")
        self.assert_rejected([node("s", "secrets", note="x" * 1001)], [], "invalid_node_config")


class CustomNodeRunTest(unittest.TestCase):
    def test_custom_node_passes_findings_to_every_output(self):
        nodes = [node("t", "trigger"), node("s", "secrets"), custom("c", outputs=2),
                 node("yes", "condition", minSeverity="high"), node("no", "condition", minSeverity="critical")]
        workflow = draft(nodes, [edge("t", "s"), edge("s", "c"), edge("c", "yes", out="out1"), edge("c", "no", out="out2")])
        archive = io.BytesIO()
        with ZipFile(archive, "w") as zip_file:
            zip_file.writestr("application.properties", "app.password=synthetic-custom-node")
        report = RunReport(runId="r", workflowId="w", nodes=[NodeResult(nodeId=n["id"]) for n in nodes])
        execute_plan(Mock(), report, plan_run(workflow), "src", archive.getvalue())
        results = {result.nodeId: result for result in report.nodes}
        self.assertEqual(report.status, "succeeded")
        self.assertEqual(results["c"].output, {"passed": 1})
        self.assertEqual(results["yes"].output, {"matched": True})
        self.assertEqual(results["no"].output, {"matched": False})
        finding_id = report.findings[0].id
        self.assertEqual(results["c"].inputs[0].findingIds, [finding_id])
        self.assertEqual([(item.port, item.nodeId) for item in results["c"].outputs],
                         [("out1", "yes"), ("out2", "no")])
        self.assertEqual(results["yes"].inputs[0].findingIds, [finding_id])

    def test_count_and_regex_send_data_only_to_the_matching_branch(self):
        nodes = [
            node("t", "trigger"), node("s", "secrets"),
            node("count", "condition", conditionMode="count", comparison="ge", threshold=1),
            node("regex", "condition", conditionMode="regex", field="file", pattern=r"\.properties$"),
            custom("selected"), custom("skipped"),
        ]
        workflow = draft(nodes, [
            edge("t", "s"), edge("s", "count"), edge("count", "regex", out="true"),
            edge("regex", "selected", out="true"), edge("regex", "skipped", out="false"),
        ])
        archive = io.BytesIO()
        with ZipFile(archive, "w") as project:
            project.writestr("application.properties", "app.password=synthetic-branch-test")
        report = RunReport(runId="run", workflowId="workflow", nodes=[NodeResult(nodeId=n["id"]) for n in nodes])
        execute_plan(Mock(), report, plan_run(workflow), "source", archive.getvalue())
        results = {result.nodeId: result for result in report.nodes}
        self.assertEqual(results["count"].output, {"mode": "count", "count": 1, "matched": True})
        self.assertEqual(results["regex"].output, {"mode": "regex", "count": 1, "matched": True})
        self.assertEqual([item.port for item in results["regex"].outputs], ["true"])
        self.assertEqual(results["selected"].inputs[0].findingCount, 1)
        self.assertEqual(results["skipped"].status, "skipped")
        self.assertEqual(results["skipped"].inputs, [])

    def test_unsupported_regex_is_rejected_before_running(self):
        workflow = draft(
            [node("t", "trigger"), node("rx", "condition", conditionMode="regex", field="file", pattern=r"(?=secret)")],
            [edge("t", "rx")],
        )
        with self.assertRaises(ApiProblem) as context:
            plan_run(workflow)
        self.assertEqual(context.exception.code, "invalid_condition_regex")


class TemplateStorage:
    def __init__(self):
        self.templates = []

    def initialize(self, **_):
        pass

    def list_node_templates(self):
        return list(reversed(self.templates))

    def count_node_templates(self):
        return len(self.templates)

    def save_node_template(self, template):
        self.templates.append(template)

    def delete_node_template(self, template_id):
        before = len(self.templates)
        self.templates = [t for t in self.templates if t.id != template_id]
        return len(self.templates) < before


class NodeTemplateApiTest(unittest.TestCase):
    def setUp(self):
        self.storage = TemplateStorage()
        patcher = mock.patch("backend.main.Storage", return_value=self.storage)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.client = TestClient(create_app("unused"))

    def test_save_list_and_remove(self):
        saved = self.client.post("/node-templates", json={
            "name": "Проверка ревьюера", "type": "custom", "config": custom("x", inputs=2, outputs=3)["config"]})
        self.assertEqual(saved.status_code, 201)
        note = self.client.post("/node-templates", json={
            "name": "Секреты с пояснением", "type": "secrets", "config": {"note": "Сначала смотрим .env"}})
        self.assertEqual(note.status_code, 201)
        listed = self.client.get("/node-templates").json()
        self.assertEqual([item["name"] for item in listed], ["Секреты с пояснением", "Проверка ревьюера"])
        self.assertEqual(listed[1]["config"]["outputs"], 3)
        self.assertEqual(self.client.post(f"/node-templates/{saved.json()['id']}/remove").status_code, 204)
        self.assertEqual(self.client.post(f"/node-templates/{saved.json()['id']}/remove").status_code, 404)
        self.assertEqual(len(self.client.get("/node-templates").json()), 1)

    def test_invalid_templates_are_rejected(self):
        self.assertEqual(self.client.post("/node-templates", json={"name": "T", "type": "trigger"}).status_code, 422)
        bad = custom("x")["config"] | {"color": "javascript:alert(1)"}
        response = self.client.post("/node-templates", json={"name": "Bad", "type": "custom", "config": bad})
        self.assertEqual((response.status_code, response.json()["code"]), (422, "invalid_node_config"))
        self.assertEqual(self.client.post("/node-templates", json={"name": "", "type": "ai"}).status_code, 422)


if __name__ == "__main__":
    unittest.main()
