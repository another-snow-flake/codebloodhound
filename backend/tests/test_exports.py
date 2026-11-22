import io
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from fastapi.testclient import TestClient

from backend.main import create_app
from backend.schemas import Finding, NodeResult, RunReport
from backend.sources import find_secrets


class ExportFindingsTest(unittest.TestCase):
    def setUp(self):
        archive = io.BytesIO()
        with ZipFile(archive, "w") as project:
            project.writestr("bundle/project/build.gradle.kts", "")
            project.writestr("bundle/project/src/main/resources/application.yml", "service-token: synthetic-value")
            project.writestr("bundle/docs/README.md", "Training project")
        self.archive = archive.getvalue()
        self.storage = Mock()
        self.storage.get_source.return_value = self.archive
        self.report = RunReport(
            runId="r", workflowId="w", status="succeeded",
            nodes=[NodeResult(nodeId="start", output={"sourceId": "source"})],
        )
        self.storage.get_run.return_value = self.report
        with patch("backend.main.Storage", return_value=self.storage):
            self.client = TestClient(create_app("unused"))
        self.addCleanup(self.client.close)

    def test_export_uses_organizer_fields_and_recovers_legacy_secret_class(self):
        secret, = find_secrets(self.archive)
        self.report.findings = [
            secret.model_copy(update={"secretClass": None}),
            Finding(
                id="sast", scanner="sast", ruleId="credentialed-cors",
                file="bundle/project/src/main/kotlin/App.kt", line=5, severity="medium", message="Review CORS.",
            ),
            Finding(
                id="sca", scanner="sca", ruleId="vulnerable-dependency",
                file="bundle/project/build.gradle.kts", line=3, severity="critical",
                message="Review the advisory.", group="test.library", artifact="example", version="1.0",
                advisoryId="GHSA-example", cve="CVE-2099-12345",
            ),
        ]
        response = self.client.get("/runs/r/findings.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-disposition"], 'attachment; filename="findings.json"')
        self.storage.get_source.assert_called_once_with("source")
        self.assertNotIn("synthetic-value", response.text)
        self.assertEqual(response.json()["findings"], [
            {
                "category": "SECRET", "path": "src/main/resources/application.yml",
                "class": "configuration-token", "line": 1, "severity": "HIGH", "description": secret.message,
            },
            {
                "category": "SAST", "path": "src/main/kotlin/App.kt", "class": "credentialed-cors",
                "line": 5, "severity": "MEDIUM", "description": "Review CORS.",
            },
            {
                "category": "SCA", "path": "build.gradle.kts", "group": "test.library", "artifact": "example",
                "version": "1.0", "advisoryId": "GHSA-example", "severity": "CRITICAL",
                "description": "Review the advisory.",
            },
        ])

    def test_export_path_stays_stable_when_other_modules_were_not_scanned(self):
        project_bytes = io.BytesIO()
        with ZipFile(project_bytes, "w") as project:
            project.writestr("backend/src/main/resources/application.properties", "app.password=training-value")
            project.writestr("web/config.js", 'export const apiKey = "training-api-key";')
        self.storage.get_source.return_value = project_bytes.getvalue()
        self.report.findings = find_secrets(project_bytes.getvalue(), plugins=("javascript",))
        full = self.client.get("/runs/r/findings.json").json()["findings"]
        self.assertEqual(len(full), 2)
        self.report.findings = [finding for finding in self.report.findings if finding.file.startswith("backend/")]
        scoped = self.client.get("/runs/r/findings.json").json()["findings"]
        self.assertEqual(scoped, [finding for finding in full if finding["path"].startswith("backend/")])
        self.assertEqual(scoped[0]["path"], "backend/src/main/resources/application.properties")

    def test_empty_report_downloads_and_running_report_cannot_be_exported(self):
        response = self.client.get("/runs/r/findings.json")
        self.assertEqual(response.json(), {"findings": []})
        self.storage.get_source.assert_not_called()

        self.report.status = "running"
        response = self.client.get("/runs/r/findings.json")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "run_in_progress")
