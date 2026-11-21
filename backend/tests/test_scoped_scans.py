import io
import unittest
from unittest.mock import Mock
from zipfile import ZipFile

from backend.accounts import password_hash, verify_password
from backend.runner import execute_plan, plan_run, validate_edges
from backend.schemas import ApiProblem, RunReport, Workflow
from backend.sources import find_secrets


class ScopedScannerTest(unittest.TestCase):
    def setUp(self):
        archive = io.BytesIO()
        with ZipFile(archive, "w") as project:
            project.writestr("training/src/server.py", 'api_key: str = "synthetic-python"\neval(user_input)\n')
            project.writestr("training/src/page.ts", 'export const apiKey = "synthetic-js";\nel.innerHTML = input;\n')
            project.writestr("training/src-old/settings.py", 'password = "synthetic-outside"\neval(user_input)\n')
            project.writestr("training/application.properties", "app.password=synthetic-config")
        self.archive = archive.getvalue()

    def workflow(self, scope, plugins=("python", "javascript")):
        nodes = [("t", "trigger", {}), ("s", "secrets", {}), ("a", "sast", {})]
        edges = [{"id": "start", "source": "t", "target": "s"}, {"id": "scan", "source": "s", "target": "a"}]
        if scope is not None:
            nodes.append(("path", "source", {"path": scope}))
            edges.extend(
                {"id": f"scope-{target}", "source": "path", "target": target, "targetHandle": "source"}
                for target in ("s", "a")
            )
        return Workflow.model_validate({
            "id": "w", "name": "Scoped training scan", "languagePlugins": list(plugins) if plugins is not None else None,
            "nodes": [{"id": key, "type": kind, "config": config, "position": {"x": 0, "y": 0}}
                      for key, kind, config in nodes],
            "edges": edges,
        })

    def run_workflow(self, scope, plugins=("python", "javascript")):
        workflow = self.workflow(scope, plugins)
        report = RunReport.for_workflow(workflow)
        execute_plan(Mock(), report, plan_run(workflow), "archive", self.archive)
        return report

    def test_unconnected_scope_scans_the_entire_project_using_enabled_plugins(self):
        self.assertEqual([f.file for f in find_secrets(self.archive)], ["training/application.properties"])
        report = self.run_workflow(None)
        self.assertEqual(report.status, "succeeded")
        self.assertEqual(len(report.findings), 7)

    def test_every_language_is_scanned_without_account_plugins(self):
        for plugins in (None, ()):  # a shared workflow and an account that never chose a language
            report = self.run_workflow(None, plugins)
            self.assertEqual(len(report.findings), 7)
            self.assertTrue({"training/src/server.py", "training/src/page.ts"} <= {f.file for f in report.findings})

    def test_folder_matches_exactly_and_keeps_both_language_plugins(self):
        report = self.run_workflow("src")
        self.assertEqual(report.status, "succeeded")
        self.assertEqual({f.file for f in report.findings}, {"training/src/server.py", "training/src/page.ts"})
        self.assertEqual(len(report.findings), 4)
        sast = next(node for node in report.nodes if node.nodeId == "a")
        self.assertEqual(sast.output["sourcePath"], "training/src")
        self.assertEqual(next(edge.sourcePath for edge in sast.inputs if edge.port == "source"), "training/src")

    def test_exact_path_and_absent_scope_cannot_fall_back_to_whole_project(self):
        report = self.run_workflow("src/server.py")
        self.assertEqual({f.file for f in report.findings}, {"training/src/server.py"})
        report = self.run_workflow("missing")
        self.assertEqual(report.status, "failed")
        self.assertEqual(report.findings, [])
        self.assertEqual({node.nodeId: node.status for node in report.nodes},
                         {"t": "succeeded", "path": "failed", "s": "skipped", "a": "skipped"})

    def test_traversal_and_crosswired_ports_are_rejected(self):
        with self.assertRaises(ApiProblem) as error:
            validate_edges(self.workflow("../outside"))
        self.assertEqual(error.exception.code, "invalid_scan_source")
        workflow = self.workflow("src")
        workflow.edges[-1].targetHandle = None
        with self.assertRaises(ApiProblem) as error:
            validate_edges(workflow)
        self.assertEqual(error.exception.code, "invalid_scan_source_edge")


class PasswordHashTest(unittest.TestCase):
    def test_passwords_are_salted(self):
        stored = password_hash("synthetic-strong-passphrase")
        self.assertNotEqual(stored, password_hash("synthetic-strong-passphrase"))
        self.assertTrue(verify_password("synthetic-strong-passphrase", stored))
        self.assertFalse(verify_password("wrong-strong-passphrase", stored))
