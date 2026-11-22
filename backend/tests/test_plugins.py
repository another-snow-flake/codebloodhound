import io
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch
from zipfile import ZipFile

from fastapi.testclient import TestClient

from backend.accounts import Account
from backend.main import create_app
from backend.runner import execute_plan, plan_run, validate_edges
from backend.schemas import ApiProblem, RunReport, Workflow, WorkflowDraft
from backend.user_plugins import UserPlugin
from backend.workflow_templates import make_public_draft


def node(node_id, kind, **config):
    return {"id": node_id, "type": kind, "position": {"x": 0, "y": 0}, "config": config}


def edge(source, target, out=None, into=None):
    item = {"id": f"{source}-{target}-{out}-{into}", "source": source, "target": target}
    if out:
        item["sourceHandle"] = out
    if into:
        item["targetHandle"] = into
    return item


def plugin(node_id, inner_nodes, inner_edges, inputs=1, outputs=2, **extra):
    config = {"title": "Ревью секретов", "color": "#2d6cdf", "inputs": inputs, "outputs": outputs,
              "graph": {"nodes": inner_nodes, "edges": inner_edges}, **extra}
    return node(node_id, "plugin", **config)


def ports(inputs, outputs):
    return ([node(f"i{k}", "plugin_input", index=k) for k in range(1, inputs + 1)]
            + [node(f"o{k}", "plugin_output", index=k) for k in range(1, outputs + 1)])


# inside: input 1 -> SAST -> condition(high); "yes" -> output 1, "no" -> output 2
BRANCHING = (
    ports(1, 2) + [node("a", "sast"), node("c", "condition", minSeverity="high", note="private note")],
    [edge("i1", "a"), edge("a", "c"), edge("c", "o1", out="true"), edge("c", "o2", out="false")],
)


def workflow(nodes, edges):
    return Workflow.model_validate({"id": "w", "name": "Plugin run", "nodes": nodes, "edges": edges})


def archive():
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as project:
        project.writestr("app.properties", "app.password=synthetic-plugin-test")
        project.writestr("src/Repo.kt", 'fun find(id: String) = jdbc.queryForList("SELECT * FROM t WHERE id = $id")\n')
    return buffer.getvalue()


def run(flow):
    report = RunReport.for_workflow(flow)
    execute_plan(Mock(), report, plan_run(flow), "src", archive())
    return report, {result.nodeId: result for result in report.nodes}


class PluginValidationTest(unittest.TestCase):
    def assert_rejected(self, plugin_node, code="invalid_plugin"):
        draft = WorkflowDraft.model_validate({"name": "W", "nodes": [node("t", "trigger"), plugin_node], "edges": []})
        with self.assertRaises(ApiProblem) as error:
            validate_edges(draft)
        self.assertEqual(error.exception.code, code)

    def test_ports_must_match_input_and_output_nodes(self):
        inner, inner_edges = BRANCHING
        validate_edges(WorkflowDraft.model_validate({"name": "W", "nodes": [plugin("p", inner, inner_edges)], "edges": []}))
        self.assert_rejected(plugin("p", inner, inner_edges, outputs=3))  # no output node 3
        self.assert_rejected(plugin("p", inner, inner_edges, inputs=2))   # no input node 2
        self.assert_rejected(plugin("p", inner + [node("o9", "plugin_output", index=2)], inner_edges))  # two outputs 2
        self.assert_rejected(plugin("p", inner, inner_edges, outputs=0), "invalid_node_config")

    def test_only_steps_belong_inside_and_every_node_is_connected(self):
        inner, inner_edges = BRANCHING
        for extra in (node("t2", "trigger"), plugin("nested", *BRANCHING)):
            with self.subTest(kind=extra["type"]):
                self.assert_rejected(plugin("p", inner + [extra], inner_edges))
        self.assert_rejected(plugin("p", inner + [node("loose", "secrets")], inner_edges))  # not connected
        self.assert_rejected(plugin("p", inner, inner_edges[:-1]))  # output 2 has no incoming edge
        self.assert_rejected(plugin("p", {"nodes": "x"}, []))
        self.assert_rejected(plugin("p", inner, inner_edges + [edge("c", "a", out="true")]))  # a cycle


class PluginRunTest(unittest.TestCase):
    def test_plugin_input_can_supply_scanner_scope_and_flow(self):
        inner = ports(1, 1) + [node("scan", "secrets")]
        step = plugin("p", inner, [edge("i1", "scan", into="source"), edge("scan", "o1")], outputs=1)
        unscoped, results = run(workflow([node("t", "trigger"), step], [edge("t", "p")]))
        self.assertEqual(len(unscoped.findings), 1)
        self.assertEqual(results["p/scan"].output["sourcePath"], ".")
        scoped, results = run(workflow([node("t", "trigger"), node("scope", "source", path="src"), step],
                                       [edge("t", "p"), edge("scope", "p", into="source")]))
        self.assertEqual((scoped.status, scoped.findings), ("succeeded", []))
        self.assertEqual(results["p/scan"].output["sourcePath"], "src")

    def test_plugin_can_notify_after_a_scan(self):
        inner = ports(1, 1) + [node("scan", "secrets"), node("send", "notify", webhookRef="team")]
        step = plugin("p", inner, [edge("i1", "scan"), edge("scan", "send"), edge("send", "o1")], outputs=1)
        with patch("backend.runner.send_webhook", return_value=204) as send:
            report, _ = run(workflow([node("t", "trigger"), step], [edge("t", "p")]))
        self.assertEqual(report.status, "succeeded")
        self.assertEqual(send.call_args.args[0], "team")

    def test_plugin_runs_its_graph_and_only_the_active_output_continues(self):
        flow = workflow(
            [node("t", "trigger"), node("s", "secrets"), plugin("p", *BRANCHING),
             node("yes", "custom", title="Да", color="#2f6b4f", inputs=1, outputs=1),
             node("no", "custom", title="Нет", color="#b3261e", inputs=1, outputs=1)],
            [edge("t", "s"), edge("s", "p"), edge("p", "yes", out="out1"), edge("p", "no", out="out2")],
        )
        report, results = run(flow)
        self.assertEqual(report.status, "succeeded")
        self.assertEqual({f.scanner for f in report.findings}, {"secrets", "sast"})
        self.assertEqual(results["p/a"].status, "succeeded")  # the SAST node inside the plugin ran
        self.assertEqual(results["p/c"].output["matched"], True)
        self.assertEqual(results["yes"].output, {"passed": 2})  # secret + SQL injection reached output 1
        self.assertEqual(results["no"].status, "skipped")
        self.assertEqual(results["p"].status, "succeeded")
        self.assertEqual(results["p"].label, "Ревью секретов")
        self.assertEqual(results["p/i1"].portIndex, 1)
        self.assertEqual(results["p/o2"].portIndex, 2)
        self.assertEqual(results["p"].output, {"innerNodes": 5, "findings": 1})
        self.assertEqual([transfer.port for transfer in results["p"].outputs], ["out1"])
        self.assertEqual(results["p"].inputs[0].findingCount, 1)
        # inner rows follow the plugin row in the report
        ids = [result.nodeId for result in report.nodes]
        self.assertEqual(ids[ids.index("p") + 1:ids.index("p") + 6], ["p/i1", "p/o1", "p/o2", "p/a", "p/c"])

    def test_two_inputs_merge_and_every_input_must_be_connected(self):
        inner = ports(2, 1)
        inner_edges = [edge("i1", "o1"), edge("i2", "o1")]
        nodes = [node("t", "trigger"), node("s", "secrets"), node("a", "sast"), plugin("p", inner, inner_edges, inputs=2, outputs=1),
                 node("end", "custom", title="Итог", color="#2f6b4f", inputs=1, outputs=0)]
        flow = workflow(nodes, [edge("t", "s"), edge("t", "a"), edge("s", "p", into="in1"), edge("a", "p", into="in2"), edge("p", "end")])
        report, results = run(flow)
        self.assertEqual(results["end"].output, {"passed": 2})
        self.assertEqual([transfer.port for transfer in results["p"].inputs], ["in1", "in2"])
        with self.assertRaises(ApiProblem) as error:
            plan_run(workflow(nodes, [edge("t", "s"), edge("t", "a"), edge("s", "p", into="in1"), edge("p", "end")]))
        self.assertEqual(error.exception.code, "plugin_input_unconnected")

    def test_inner_failure_marks_the_plugin_failed(self):
        inner = ports(1, 1) + [node("deps", "sca")]  # no vulnerability catalog in the archive
        flow = workflow([node("t", "trigger"), plugin("p", inner, [edge("i1", "deps"), edge("deps", "o1")], outputs=1)],
                        [edge("t", "p")])
        report, results = run(flow)
        self.assertEqual((report.status, results["p"].status), ("failed", "failed"))
        self.assertTrue(results["p"].error)

    def test_plugin_input_and_output_nodes_cannot_run_outside_a_plugin(self):
        with self.assertRaises(ApiProblem) as error:
            plan_run(workflow([node("t", "trigger"), node("i", "plugin_input", index=1)], []))
        self.assertEqual(error.exception.code, "unsupported_node")


class PluginApiTest(unittest.TestCase):
    def setUp(self):
        self.storage = Mock()
        self.storage.session_account.return_value = Account(id="owner", username="owner", languagePlugins=[])
        self.storage.save_plugin.side_effect = lambda plugin_id, account, draft, create: UserPlugin(
            id=plugin_id, author=account.username, owned=True, updatedAt=datetime.now(timezone.utc), **draft.model_dump())
        with patch("backend.main.Storage", return_value=self.storage):
            self.client = TestClient(create_app("unused"))
        self.addCleanup(self.client.close)

    def save(self, config):
        return self.client.post("/plugins", json={"description": "Проверка", "config": config},
                                headers={"X-CodeBloodhound-Session": "a" * 43})

    def test_graph_plugins_are_validated_and_old_single_node_plugins_still_save(self):
        config = plugin("p", *BRANCHING)["config"]
        self.assertEqual(self.save(config).status_code, 201)
        self.assertEqual(self.save({**config, "outputs": 3}).json()["code"], "invalid_plugin")
        self.assertEqual(self.save({**config, "webhookRef": "x"}).json()["code"], "invalid_node_config")
        legacy = {"title": "Старый", "color": "#2f6b4f", "inputs": 1, "outputs": 1, "scanner": "secrets"}
        self.assertEqual(self.save(legacy).status_code, 201)


class PluginTemplateTest(unittest.TestCase):
    def test_published_copy_keeps_the_graph_without_private_notes(self):
        flow = workflow([node("t", "trigger"), plugin("p", *BRANCHING, note="team only")], [edge("t", "p")])
        draft = make_public_draft(flow, "Шаблон")
        config = draft.nodes[1].config
        self.assertNotIn("note", config)
        inner = {item["id"]: item for item in config["graph"]["nodes"]}
        self.assertEqual(inner["c"]["config"], {"minSeverity": "high"})  # the inner note is gone
        self.assertEqual(inner["o2"]["config"], {"index": 2})
        plan_run(draft)


if __name__ == "__main__":
    unittest.main()
