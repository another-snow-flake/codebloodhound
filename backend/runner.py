import re
from collections.abc import Callable
from graphlib import CycleError, TopologicalSorter
from typing import NamedTuple

from .ai import MAX_GROUPS, explain_findings, group_findings, select_priorities, template_analysis
from .llm import LlmError, ModelSpec, client_for, load_llm
from .sca import CatalogUnavailable, find_vulnerable_dependencies
from .sast import find_kotlin_issues
from .schemas import AiAnalysis, ApiProblem, Edge, Finding, Node, RunReport, WorkflowDraft
from .sources import find_secrets
from .storage import Storage
from .webhooks import WEBHOOK_REF, WebhookError, send_webhook


SEVERITY_RANK = {severity: rank for rank, severity in enumerate(("low", "medium", "high", "critical"))}
SCANNERS = {"secrets": find_secrets, "sca": find_vulnerable_dependencies, "sast": find_kotlin_issues}
SUPPORTED_NODES = {"trigger", "condition", "ai", "notify", "custom", *SCANNERS}
MAX_PORTS = 4
MAX_NOTE = 1000
COLOR = re.compile(r"#[0-9a-fA-F]{6}")


def _port_count(node: Node, key: str) -> int:
    return node.config[key]  # validated by validate_node_config before use


def validate_node_config(node: Node) -> None:
    """Config shared by every node (the note) and the custom node's own settings."""
    note = node.config.get("note", "")
    if not isinstance(note, str) or len(note) > MAX_NOTE:
        raise ApiProblem(422, "invalid_node_config", f"A node note must be text up to {MAX_NOTE} characters.")
    if node.type != "custom":
        return
    title, color = node.config.get("title"), node.config.get("color")
    inputs, outputs = node.config.get("inputs"), node.config.get("outputs")
    if (
        not isinstance(title, str) or not 1 <= len(title.strip()) <= 40
        or not isinstance(color, str) or not COLOR.fullmatch(color)
        or type(inputs) is not int or not 1 <= inputs <= MAX_PORTS
        or type(outputs) is not int or not 0 <= outputs <= MAX_PORTS
    ):
        raise ApiProblem(422, "invalid_node_config",
                         "A custom node needs a title up to 40 characters, a #rrggbb color, 1-4 inputs and 0-4 outputs.")


def output_handles(node: Node) -> set[str | None]:
    if node.type == "condition":
        return {"true", "false"}
    if node.type == "custom":
        count = _port_count(node, "outputs")
        return {None} if count == 1 else {f"out{number}" for number in range(1, count + 1)}
    return {None}


def input_handles(node: Node) -> set[str | None]:
    if node.type == "custom":
        count = _port_count(node, "inputs")
        return {None} if count == 1 else {f"in{number}" for number in range(1, count + 1)}
    return {None}


class ExecutionPlan(NamedTuple):
    nodes: list[Node]
    incoming: dict[str, list[Edge]]


class NodeContext(NamedTuple):
    findings: dict[str, Finding]
    analyses: dict[str, AiAnalysis]


class AiNodeResult(NamedTuple):
    output: dict
    error: str | None
    analysis: AiAnalysis | None


def validate_edges(workflow: WorkflowDraft) -> dict[str, list[Edge]]:
    nodes = {node.id: node for node in workflow.nodes}
    incoming: dict[str, list[Edge]] = {node_id: [] for node_id in nodes}
    if len(nodes) != len(workflow.nodes) or len({edge.id for edge in workflow.edges}) != len(workflow.edges):
        raise ApiProblem(422, "invalid_workflow", "Node IDs and edge IDs must be unique.")
    for node in workflow.nodes:
        validate_node_config(node)
    for edge in workflow.edges:
        if edge.source not in nodes or edge.target not in nodes:
            raise ApiProblem(422, "invalid_workflow", "Every edge must connect existing nodes.")
        source = nodes[edge.source]
        if source.type == "condition" and edge.sourceHandle not in ("true", "false"):
            raise ApiProblem(422, "invalid_workflow", "Only condition edges require a true or false sourceHandle.")
        if edge.sourceHandle not in output_handles(source):
            raise ApiProblem(422, "invalid_workflow", "An edge leaves through a port its source node does not have.")
        if edge.targetHandle not in input_handles(nodes[edge.target]):
            raise ApiProblem(422, "invalid_workflow", "An edge enters through a port its target node does not have.")
        incoming[edge.target].append(edge)
    return incoming


def plan_run(workflow: WorkflowDraft) -> ExecutionPlan:
    incoming = validate_edges(workflow)
    triggers = [node for node in workflow.nodes if node.type == "trigger"]
    if len(triggers) != 1 or incoming[triggers[0].id]:
        raise ApiProblem(422, "invalid_workflow", "A run requires one trigger with no incoming edges.")
    if triggers[0].config.get("mode", "manual") != "manual":
        raise ApiProblem(422, "unsupported_trigger", "Only manual triggers can run in this build.")

    nodes_by_id = {node.id: node for node in workflow.nodes}
    dependencies = {node_id: {edge.source for edge in edges} for node_id, edges in incoming.items()}
    try:
        ordered = [nodes_by_id[node_id] for node_id in TopologicalSorter(dependencies).static_order()]
    except CycleError as error:
        raise ApiProblem(422, "invalid_workflow", "A workflow cannot contain cycles.") from error

    if any(not incoming[node.id] for node in ordered if node.type != "trigger"):
        raise ApiProblem(422, "invalid_workflow", "Every node must be reachable from the trigger.")
    for node in ordered:
        if node.type not in SUPPORTED_NODES:
            raise ApiProblem(422, "unsupported_node", f"The {node.type} node cannot run in this build yet.")
        if node.type == "condition":
            minimum = node.config.get("minSeverity")
            if not isinstance(minimum, str) or minimum not in SEVERITY_RANK:
                raise ApiProblem(422, "invalid_node_config", "Condition requires a valid config.minSeverity.")
        if node.type == "notify":
            ref = node.config.get("webhookRef")
            if not isinstance(ref, str) or not WEBHOOK_REF.fullmatch(ref):
                raise ApiProblem(422, "invalid_webhook_ref", "Notification requires a valid config.webhookRef.")
    return ExecutionPlan(ordered, incoming)


def merge_analysis(report: RunReport, analysis: AiAnalysis) -> None:
    """Several AI nodes: keep the first summary, add cards for findings not explained yet."""
    if report.aiAnalysis is None:
        report.aiAnalysis = analysis.model_copy(deep=True)
        return
    current = report.aiAnalysis
    known = {item.findingId for item in current.recommendations}
    used_ids = {group.id for group in current.groups}
    next_number = len(used_ids) + 1
    actions = {item.groupId: item.action for item in current.priorities}
    incoming_actions = {item.groupId: item.action for item in analysis.priorities}
    for group in analysis.groups:
        if known.issuperset(group.findingIds):
            continue
        while f"G{next_number}" in used_ids:
            next_number += 1
        group_id = f"G{next_number}"
        next_number += 1
        current.groups.append(group.model_copy(update={"id": group_id}))
        actions[group_id] = incoming_actions.get(group.id, group.action)
    current.recommendations.extend(item for item in analysis.recommendations if item.findingId not in known)
    current.priorities = select_priorities(current.groups, actions)


def run_ai(
    report: RunReport, findings: list[Finding], publish: Callable[[dict], None] | None = None,
    model_spec: ModelSpec | None = None,
) -> AiNodeResult:
    """Explain the findings that reached the AI node.

    `publish(output)` stores the current stage so the editor can show it while the
    model works. An unavailable model is not a node failure: the findings still flow
    to the next nodes, only without recommendations.
    """
    total = len(findings)
    progress: dict = {"total": total}

    def stage(name: str, **details):
        progress.update(details, stage=name)  # keep earlier details, e.g. how many findings were sent
        if publish:
            publish(dict(progress))

    model = None
    try:
        # the model was pinned when the run started; without one, the server environment decides
        client = (client_for(model_spec) if model_spec else load_llm()) if findings else None
        if getattr(client, "provider", None) and getattr(client, "model", None):
            model = f"{client.provider}:{client.model}"
            progress["model"] = model
        analysis = explain_findings(findings, client, stage)
    except LlmError as error:
        # the model is unavailable or its answers failed validation twice: cards from the scanner
        # rules keep the report readable, and errorCode tells the editor why the model was skipped
        analysis = template_analysis(findings)
        merge_analysis(report, analysis)
        output = {"aiAvailable": False, "fallback": True, "stage": "done", "errorCode": error.code,
                  "explained": len(analysis.recommendations), "total": total}
        if model:
            output["model"] = model
        return AiNodeResult(output, f"AI unavailable: {error}", analysis)

    merge_analysis(report, analysis)
    explained = sum(len(group.findingIds) for group in analysis.groups if group.source == "model")
    output = {"aiAvailable": True, "stage": "done", "explained": explained, "total": total}
    if progress.get("cached"):
        output["cached"] = True
    if model:
        output["model"] = model
    groups = len(group_findings(findings))
    if groups > MAX_GROUPS:
        output["limit"] = MAX_GROUPS
    return AiNodeResult(output, None, analysis)


def execute_plan(
    storage: Storage, report: RunReport, plan: ExecutionPlan, source_id: str, archive: bytes,
    model: ModelSpec | None = None,
):
    results = {result.nodeId: result for result in report.nodes}
    active_contexts: dict[tuple[str, str | None], NodeContext] = {}
    report.status = "running"
    storage.save_run(report)
    for node in plan.nodes:
        result = results[node.id]
        active_inputs = [
            active_contexts[edge.source, edge.sourceHandle]
            for edge in plan.incoming[node.id]
            if (edge.source, edge.sourceHandle) in active_contexts
        ]
        if node.type != "trigger" and not active_inputs:
            result.status = "skipped"
            storage.save_run(report)
            continue

        result.status = "running"
        storage.save_run(report)
        context = NodeContext(
            {key: finding for item in active_inputs for key, finding in item.findings.items()},
            {key: analysis for item in active_inputs for key, analysis in item.analyses.items()},
        )
        handle = None
        try:
            if node.type == "trigger":
                result.output = {"sourceId": source_id}
            elif node.type in SCANNERS:
                findings = SCANNERS[node.type](archive)
                report.findings.extend(findings)
                context.findings.update((finding.id, finding) for finding in findings)
                result.output = {"findings": [finding.model_dump(mode="json", exclude_unset=True) for finding in findings]}
            elif node.type == "condition":
                minimum_rank = SEVERITY_RANK[node.config["minSeverity"]]
                matched = any(SEVERITY_RANK[finding.severity] >= minimum_rank for finding in context.findings.values())
                result.output = {"matched": matched}
                handle = "true" if matched else "false"
            elif node.type == "ai":
                def publish(output: dict, result=result):
                    result.output = output
                    storage.save_run(report)

                outcome = run_ai(report, list(context.findings.values()), publish, model)
                result.output, result.error = outcome.output, outcome.error
                if outcome.analysis is not None:
                    context.analyses[node.id] = outcome.analysis
            elif node.type == "custom":
                # a user-defined step: passes the findings it received to every output
                result.output = {"passed": len(context.findings)}
            elif node.type == "notify":
                status_code = send_webhook(node.config["webhookRef"], {
                    "runId": report.runId, "workflowId": report.workflowId, "nodeId": node.id,
                    "findings": [
                        finding.model_dump(mode="json", exclude_none=True) for finding in context.findings.values()
                    ],
                    "aiAnalyses": [
                        {"nodeId": node_id, **analysis.model_dump(mode="json")}
                        for node_id, analysis in context.analyses.items()
                    ],
                })
                result.output = {"delivered": True, "statusCode": status_code}
            result.status = "succeeded"
            for active in (output_handles(node) if node.type == "custom" else {handle}):
                active_contexts[node.id, active] = context
        except WebhookError as error:
            result.status = "failed"
            result.error = str(error)
            result.output = {"delivered": False, "errorCode": error.code}
            if error.status_code is not None:
                result.output["statusCode"] = error.status_code
        except CatalogUnavailable as error:
            result.status = "failed"
            result.error = str(error)
        except Exception:
            result.status = "failed"
            result.error = "Node execution failed."
        storage.save_run(report)

    report.status = "failed" if any(node.status == "failed" for node in report.nodes) else "succeeded"
    storage.save_run(report)
