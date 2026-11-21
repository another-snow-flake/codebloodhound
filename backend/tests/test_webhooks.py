import io
import json
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

from backend.llm import LlmError
from backend.runner import execute_plan, plan_run
from backend.schemas import NodeResult, RunReport, WorkflowDraft
from backend.webhooks import WebhookError, configured_webhooks


class WorkflowWebhookTest(unittest.TestCase):
    def run_workflow(self, minimum, send, model_error=None):
        nodes = [
            ("start", "trigger", {}), ("scan", "secrets", {}),
            ("ai-main", "ai", {}), ("ai-other", "ai", {}),
            ("condition", "condition", {"minSeverity": minimum}),
            ("notify", "notify", {"webhookRef": "team"}),
        ]
        connections = [("start", "scan"), ("scan", "ai-main"), ("scan", "ai-other"), ("ai-main", "condition")]
        workflow = WorkflowDraft.model_validate({
            "name": "Webhook",
            "nodes": [
                {"id": key, "type": kind, "position": {"x": i, "y": 0}, "config": config}
                for i, (key, kind, config) in enumerate(nodes)
            ],
            "edges": [{"id": f"{source}-{target}", "source": source, "target": target} for source, target in connections]
            + [{"id": "true", "source": "condition", "target": "notify", "sourceHandle": "true"}],
        })
        content = io.BytesIO()
        with ZipFile(content, "w") as archive:
            archive.writestr("application.properties", "test.password=synthetic-webhook-test")
        report = RunReport(runId="r", workflowId="w", findings=[], nodes=[NodeResult(nodeId=key) for key, *_ in nodes])

        class Model:
            summaries = iter(("First AI node", "Second AI node"))

            def complete(self, messages, **options):
                return json.dumps({
                    "summary": next(self.summaries),
                    "groups": [{"groupId": "G1", "title": "Secret", "action": "Rotate it", "explanation": "Finding detected"}],
                })

        with patch("backend.runner.load_llm", return_value=Model(), side_effect=model_error):
            with patch("backend.runner.send_webhook", send):
                execute_plan(Mock(), report, plan_run(workflow), "source", content.getvalue())
        return report

    def test_true_branch_sends_only_its_findings_and_ai_results(self):
        send = Mock(return_value=204)
        report = self.run_workflow("high", send)
        self.assertEqual(report.status, "succeeded")
        send.assert_called_once()
        ref, payload = send.call_args.args
        self.assertEqual(ref, "team")
        self.assertEqual([f["id"] for f in payload["findings"]], [report.findings[0].id])
        self.assertEqual([a["nodeId"] for a in payload["aiAnalyses"]], ["ai-main"])
        self.assertEqual(payload["aiAnalyses"][0]["summary"], "First AI node")
        self.assertNotIn("synthetic-webhook-test", json.dumps(payload))

    def test_false_branch_does_not_send(self):
        send = Mock(return_value=204)
        report = self.run_workflow("critical", send)
        send.assert_not_called()
        self.assertEqual(report.nodes[-1].status, "skipped")

    def test_delivery_failure_keeps_report_and_http_code(self):
        send = Mock(side_effect=WebhookError("webhook_rejected", "Receiver failed.", 503))
        report = self.run_workflow("high", send)
        self.assertEqual(report.status, "failed")
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.nodes[-1].output, {"delivered": False, "errorCode": "webhook_rejected", "statusCode": 503})

    def test_webhook_sends_findings_when_ai_is_unavailable(self):
        send = Mock(return_value=204)
        report = self.run_workflow("high", send, LlmError("not_configured", "No model"))
        send.assert_called_once()
        _, payload = send.call_args.args
        self.assertEqual(report.status, "succeeded")
        self.assertEqual(len(payload["findings"]), 1)
        # without a model the AI node still sends cards built from scanner rules, marked as such
        self.assertEqual([analysis["source"] for analysis in payload["aiAnalyses"]], ["template"])

    def test_non_http_targets_are_rejected(self):
        with patch.dict("os.environ", {"CYBER_GARDEN_WEBHOOKS": '{"team":"file:///report"}'}):
            with self.assertRaises(WebhookError) as context:
                configured_webhooks()
        self.assertEqual(context.exception.code, "invalid_webhook_settings")
