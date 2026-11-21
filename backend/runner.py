import re
from collections.abc import Callable
from graphlib import CycleError, TopologicalSorter
from itertools import islice
from pathlib import PurePosixPath
from typing import NamedTuple

from pydantic import ValidationError

from .ai import MAX_GROUPS, explain_findings, group_findings, select_priorities, template_analysis
from .conditions import evaluate_condition, validate_condition
from .language_plugins import LANGUAGE_SUFFIXES

# Secret scanning and SAST cover every supported language; there is no per-account choice anymore.
ALL_LANGUAGES = tuple(LANGUAGE_SUFFIXES)
from .llm import LlmError, ModelSpec, client_for, load_llm
from .sca import CatalogUnavailable, find_vulnerable_dependencies
from .sast import find_static_issues
from .schedule import daily_schedule
from .schemas import AiAnalysis, ApiProblem, Edge, Finding, Node, NodeResult, NodeTransfer, RunReport, WorkflowDraft
from .sources import archive_scope, find_secrets, validate_scope
from .storage import Storage
from .webhooks import WEBHOOK_REF, WebhookError, send_webhook


SCANNERS = {"secrets": find_secrets, "sca": find_vulnerable_dependencies, "sast": find_static_issues}
# plugin_input and plugin_output appear only after a plugin node is unfolded for a run
SUPPORTED_NODES = {"trigger", "source", "condition", "ai", "notify", "custom", "plugin_input", "plugin_output", *SCANNERS}
MAX_PORTS = 4
MAX_NOTE = 1000
COLOR = re.compile(r"#[0-9a-fA-F]{6}")
TRANSFER_PREVIEW_SIZE = 5


def node_scanner(node: Node) -> str | None:
    if node.type == "custom":
        return node.config.get("scanner")
    return node.type if node.type in SCANNERS else None


def _port_count(node: Node, key: str) -> int:
    return node.config[key]  # validated by validate_node_config before use


def _check_ports(node: Node, *, min_outputs: int, kind: str) -> None:
    title, color = node.config.get("title"), node.config.get("color")
    inputs, outputs = node.config.get("inputs"), node.config.get("outputs")
    if (
        not isinstance(title, str) or not 1 <= len(title.strip()) <= 40
        or not isinstance(color, str) or not COLOR.fullmatch(color)
        or type(inputs) is not int or not 1 <= inputs <= MAX_PORTS
        or type(outputs) is not int or not min_outputs <= outputs <= MAX_PORTS
    ):
        raise ApiProblem(422, "invalid_node_config",
                         f"A {kind} needs a title up to 40 characters, a #rrggbb color, 1-4 inputs and {min_outputs}-4 outputs.")


def validate_node_config(node: Node) -> None:
    """Config shared by every node (the note) and the custom node's own settings."""
    note = node.config.get("note", "")
    if not isinstance(note, str) or len(note) > MAX_NOTE:
        raise ApiProblem(422, "invalid_node_config", f"A node note must be text up to {MAX_NOTE} characters.")
    if node.type == "condition":
        validate_condition(node.config)
    if node.type == "source":
        validate_scope(node.config.get("path"))
    if node.type in ("plugin_input", "plugin_output"):
        index = node.config.get("index")
        if type(index) is not int or not 1 <= index <= MAX_PORTS:
            raise ApiProblem(422, "invalid_plugin", "Plugin inputs and outputs are numbered 1-4.")
    if node.type == "plugin":
        validate_plugin(node)
    if node.type != "custom":
        return
    _check_ports(node, min_outputs=0, kind="custom node")
    scanner = node_scanner(node)
    if scanner is not None and (not isinstance(scanner, str) or scanner not in SCANNERS):
        raise ApiProblem(422, "invalid_node_config", "Choose a built-in scanner for the custom node.")
    language = node.config.get("language")
    if language is not None and (
        not isinstance(language, str) or language not in LANGUAGE_SUFFIXES or scanner not in ("secrets", "sast")
    ):
        raise ApiProblem(422, "invalid_node_config", "Choose a supported language for secret scanning or static analysis.")


def output_handles(node: Node) -> set[str | None]:
    if node.type == "condition":
        return {"true", "false"}
    if node.type in ("custom", "plugin"):
        count = _port_count(node, "outputs")
        return {None} if count == 1 else {f"out{number}" for number in range(1, count + 1)}
    if node.type == "plugin_output":
        return set()  # inside the plugin nothing leaves an output; on the canvas the plugin node's port does
    return {None}


def input_handles(node: Node) -> set[str | None]:
    if node.type in SCANNERS:
        return {None, "source"}
    if node.type in ("source", "plugin_input"):
        return set()
    if node.type == "plugin":
        count = _port_count(node, "inputs")
        return {None} if count == 1 else {f"in{number}" for number in range(1, count + 1)}
    if node.type == "custom":
        count = _port_count(node, "inputs")
        handles = {None} if count == 1 else {f"in{number}" for number in range(1, count + 1)}
        if node_scanner(node):
            handles.add("source")
        return handles
    return {None}


class PluginGroup(NamedTuple):
    """A plugin node unfolded into the run: its inner node IDs and the IDs of its input and output nodes."""
    node: Node
    inner: list[str]
    inputs: dict[int, str]
    outputs: dict[int, str]


class ExecutionPlan(NamedTuple):
    nodes: list[Node]
    incoming: dict[str, list[Edge]]
    plugins: dict[str, PluginGroup] = {}


class NodeContext(NamedTuple):
    findings: dict[str, Finding]
    analyses: dict[str, AiAnalysis]
    source_path: PurePosixPath | None = None

    def transfer(self, port: str | None, node_id: str | None = None) -> NodeTransfer:
        return NodeTransfer(
            nodeId=node_id,
            port=port,
            findingCount=len(self.findings),
            analysisCount=len(self.analyses),
            findingIds=list(islice(self.findings, TRANSFER_PREVIEW_SIZE)),
            analysisNodeIds=list(islice(self.analyses, TRANSFER_PREVIEW_SIZE)),
            sourcePath=self.source_path.as_posix() if self.source_path is not None else None,
        )


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
        if (source.type == "source") != (edge.targetHandle == "source"):
            raise ApiProblem(422, "invalid_scan_source_edge", "Connect a source node only to a scanner's source input.")
        if source.type == "condition" and edge.sourceHandle not in ("true", "false"):
            raise ApiProblem(422, "invalid_workflow", "Only condition edges require a true or false sourceHandle.")
        if edge.sourceHandle not in output_handles(source):
            raise ApiProblem(422, "invalid_workflow", "An edge leaves through a port its source node does not have.")
        if edge.targetHandle not in input_handles(nodes[edge.target]):
            raise ApiProblem(422, "invalid_workflow", "An edge enters through a port its target node does not have.")
        if edge.targetHandle == "source" and any(item.targetHandle == "source" for item in incoming[edge.target]):
            raise ApiProblem(422, "invalid_scan_source_edge", "A scanner accepts only one source node.")
        incoming[edge.target].append(edge)
    return incoming


PLUGIN_INNER_TYPES = frozenset({"plugin_input", "plugin_output", "source", "condition", "ai", "custom", *SCANNERS})
MAX_PLUGIN_NODES = 40
MAX_PLUGIN_EDGES = 80


def plugin_graph(node: Node) -> WorkflowDraft:
    graph = node.config.get("graph")
    if not isinstance(graph, dict):
        raise ApiProblem(422, "invalid_plugin", "A plugin needs its own graph of nodes and edges.")
    try:
        return WorkflowDraft.model_validate({"name": "plugin", "nodes": graph.get("nodes"), "edges": graph.get("edges")})
    except ValidationError:
        raise ApiProblem(422, "invalid_plugin", "The plugin graph is malformed.") from None


def validate_plugin(node: Node) -> None:
    """A plugin is a separate small project: one input node per input port, one output node per output port,
    and scanners, sources, conditions, AI or custom nodes between them."""
    _check_ports(node, min_outputs=1, kind="plugin")
    graph = plugin_graph(node)
    if len(graph.nodes) > MAX_PLUGIN_NODES or len(graph.edges) > MAX_PLUGIN_EDGES:
        raise ApiProblem(422, "invalid_plugin", f"A plugin holds up to {MAX_PLUGIN_NODES} nodes and {MAX_PLUGIN_EDGES} edges.")
    for inner in graph.nodes:
        if inner.type not in PLUGIN_INNER_TYPES:
            raise ApiProblem(422, "invalid_plugin",
                             "A plugin can hold scanners, sources, conditions, AI recommendations and custom nodes.")
        if "/" in inner.id:
            raise ApiProblem(422, "invalid_plugin", "Node IDs inside a plugin cannot contain a slash.")
    for kind, count in (("plugin_input", node.config["inputs"]), ("plugin_output", node.config["outputs"])):
        indexes = sorted(inner.config.get("index") for inner in graph.nodes if inner.type == kind)
        if indexes != list(range(1, count + 1)):
            raise ApiProblem(422, "invalid_plugin", "The plugin needs exactly one input node per input and one output node per output.")
    incoming = validate_edges(graph)
    try:
        tuple(TopologicalSorter({key: {edge.source for edge in edges} for key, edges in incoming.items()}).static_order())
    except CycleError:
        raise ApiProblem(422, "invalid_plugin", "A plugin cannot contain cycles.") from None
    for inner in graph.nodes:
        if inner.type not in ("plugin_input", "source") and not any(edge.targetHandle != "source" for edge in incoming[inner.id]):
            raise ApiProblem(422, "invalid_plugin", "Connect every node inside the plugin; each output needs an incoming edge.")


def expand_plugins(workflow: WorkflowDraft) -> tuple[WorkflowDraft, dict[str, PluginGroup]]:
    """Unfold every plugin node into its inner graph so the run uses the same scanners, branches and skips.

    Inner nodes get IDs "<plugin node>/<inner node>". An edge into port inK of the plugin goes to its input
    node K, an edge out of port outK leaves its output node K; both pass findings through unchanged.
    """
    plugins = {node.id: node for node in workflow.nodes if node.type == "plugin"}
    if not plugins:
        return workflow, {}
    nodes: list[Node] = []
    edges: list[Edge] = []
    groups: dict[str, PluginGroup] = {}
    for node in workflow.nodes:
        if node.type != "plugin":
            nodes.append(node)
            continue
        graph = plugin_graph(node)
        prefix = node.id + "/"
        inner = [prefix + item.id for item in graph.nodes]
        nodes.extend(item.model_copy(update={"id": prefix + item.id}) for item in graph.nodes)
        edges.extend(
            edge.model_copy(update={"id": prefix + edge.id, "source": prefix + edge.source, "target": prefix + edge.target})
            for edge in graph.edges
        )
        groups[node.id] = PluginGroup(
            node, inner,
            {item.config["index"]: prefix + item.id for item in graph.nodes if item.type == "plugin_input"},
            {item.config["index"]: prefix + item.id for item in graph.nodes if item.type == "plugin_output"},
        )
    for edge in workflow.edges:
        update = {}
        if edge.target in groups:
            update.update(target=groups[edge.target].inputs[int(edge.targetHandle[2:]) if edge.targetHandle else 1], targetHandle=None)
        if edge.source in groups:
            update.update(source=groups[edge.source].outputs[int(edge.sourceHandle[3:]) if edge.sourceHandle else 1], sourceHandle=None)
        edges.append(edge.model_copy(update=update))
    if len({node.id for node in nodes}) != len(nodes) or len({edge.id for edge in edges}) != len(edges):
        raise ApiProblem(422, "invalid_workflow", "Node IDs clash with the nodes inside a plugin.")
    targets = {edge.target for edge in edges}
    for group in groups.values():
        if any(input_id not in targets for input_id in group.inputs.values()):
            raise ApiProblem(422, "plugin_input_unconnected",
                             f"Connect every input of the plugin node «{group.node.config['title']}».")
    return WorkflowDraft.model_construct(name=workflow.name, nodes=nodes, edges=edges), groups


def plan_run(workflow: WorkflowDraft) -> ExecutionPlan:
    incoming = validate_edges(workflow)
    if any(node.type in ("plugin_input", "plugin_output") for node in workflow.nodes):
        raise ApiProblem(422, "unsupported_node", "Plugin input and output nodes belong inside a plugin.")
    triggers = [node for node in workflow.nodes if node.type == "trigger"]
    if len(triggers) != 1 or incoming[triggers[0].id]:
        raise ApiProblem(422, "invalid_workflow", "A run requires one trigger with no incoming edges.")
    mode = triggers[0].config.get("mode", "manual")
    if mode not in ("manual", "daily"):
        raise ApiProblem(422, "unsupported_trigger", "Use a manual or daily trigger.")
    if mode == "daily":
        daily_schedule(workflow)

    workflow, plugins = expand_plugins(workflow)
    if plugins:
        incoming = {node.id: [] for node in workflow.nodes}
        for edge in workflow.edges:
            incoming[edge.target].append(edge)
    nodes_by_id = {node.id: node for node in workflow.nodes}
    dependencies = {node_id: {edge.source for edge in edges} for node_id, edges in incoming.items()}
    try:
        ordered = [nodes_by_id[node_id] for node_id in TopologicalSorter(dependencies).static_order()]
    except CycleError as error:
        raise ApiProblem(422, "invalid_workflow", "A workflow cannot contain cycles.") from error

    if any(
        not any(edge.targetHandle != "source" for edge in incoming[node.id])
        for node in ordered if node.type not in ("trigger", "source")
    ):
        raise ApiProblem(422, "invalid_workflow", "Every node must be reachable from the trigger.")
    for node in ordered:
        if node.type not in SUPPORTED_NODES:
            raise ApiProblem(422, "unsupported_node", f"The {node.type} node cannot run in this build yet.")
        if node.type == "notify":
            ref = node.config.get("webhookRef")
            if not isinstance(ref, str) or not WEBHOOK_REF.fullmatch(ref):
                raise ApiProblem(422, "invalid_webhook_ref", "Notification requires a valid config.webhookRef.")
    return ExecutionPlan(ordered, incoming, plugins)


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
    add_plugin_results(report, plan)
    results = {result.nodeId: result for result in report.nodes}
    outgoing = {node.id: [] for node in plan.nodes}
    for edges in plan.incoming.values():
        for edge in edges:
            outgoing[edge.source].append(edge)
    active_contexts: dict[tuple[str, str | None], NodeContext] = {}
    unique_findings: dict[tuple, Finding] = {}
    report.status = "running"
    storage.save_run(report)
    for node in plan.nodes:
        result = results[node.id]
        active_inputs = [
            (edge, active_contexts[edge.source, edge.sourceHandle])
            for edge in plan.incoming[node.id]
            if (edge.source, edge.sourceHandle) in active_contexts
        ]
        result.inputs = [context.transfer(edge.targetHandle, edge.source) for edge, context in active_inputs]
        result.outputs = []
        flow_inputs = [context for edge, context in active_inputs if edge.targetHandle != "source"]
        scope_input = next((context for edge, context in active_inputs if edge.targetHandle == "source"), None)
        requires_source = any(edge.targetHandle == "source" for edge in plan.incoming[node.id])
        if node.type not in ("trigger", "source") and (not flow_inputs or (requires_source and scope_input is None)):
            result.status = "skipped"
            storage.save_run(report)
            continue

        result.status = "running"
        storage.save_run(report)
        context = NodeContext(
            {key: finding for item in flow_inputs for key, finding in item.findings.items()},
            {key: analysis for item in flow_inputs for key, analysis in item.analyses.items()},
        )
        handle = None
        scanner = node_scanner(node)
        try:
            if node.type == "trigger":
                result.output = {"sourceId": source_id}
            elif node.type == "source":
                path = archive_scope(archive, node.config["path"])
                context = NodeContext({}, {}, path)
                result.output = {"sourcePath": path.as_posix()}
            elif scanner is not None:
                path = scope_input.source_path if scope_input is not None else None
                if scanner == "sca":
                    findings = find_vulnerable_dependencies(archive, path)
                elif node.type == "custom" and (language := node.config.get("language")):
                    findings = SCANNERS[scanner](archive, path, language=language)
                else:
                    findings = SCANNERS[scanner](archive, path, ALL_LANGUAGES)
                canonical_findings = {}
                for finding in findings:
                    key = tuple(finding.model_dump(exclude={"id"}).values())
                    if key not in unique_findings:
                        unique_findings[key] = finding
                        report.findings.append(finding)
                    canonical = unique_findings[key]
                    canonical_findings[canonical.id] = canonical
                findings = list(canonical_findings.values())
                context.findings.update((finding.id, finding) for finding in findings)
                result.output = {"findings": [finding.model_dump(mode="json", exclude_unset=True) for finding in findings]}
                if path is not None:
                    result.output["sourcePath"] = path.as_posix()
            elif node.type == "condition":
                result.output = evaluate_condition(node.config, context.findings.values())
                handle = "true" if result.output["matched"] else "false"
            elif node.type == "ai":
                def publish(output: dict, result=result):
                    result.output = output
                    storage.save_run(report)

                outcome = run_ai(report, list(context.findings.values()), publish, model)
                result.output, result.error = outcome.output, outcome.error
                if outcome.analysis is not None:
                    context.analyses[node.id] = outcome.analysis
            elif node.type in ("custom", "plugin_input", "plugin_output"):
                # a user-defined step or a plugin port: passes the findings it received to every output
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
            handles = output_handles(node) if node.type == "custom" else {handle}
            for active in handles:
                active_contexts[node.id, active] = context
            result.outputs = [
                context.transfer(edge.sourceHandle, edge.target)
                for edge in outgoing[node.id] if edge.sourceHandle in handles
            ]
        except WebhookError as error:
            result.status = "failed"
            result.error = str(error)
            result.output = {"delivered": False, "errorCode": error.code}
            if error.status_code is not None:
                result.output["statusCode"] = error.status_code
        except CatalogUnavailable as error:
            result.status = "failed"
            result.error = str(error)
        except ApiProblem as error:
            result.status = "failed"
            result.error = str(error)
            result.output = {"errorCode": error.code}
        except Exception:
            result.status = "failed"
            result.error = "Node execution failed."
        if "/" in node.id and node.id.split("/", 1)[0] in plan.plugins:
            summarize_plugin(results, plan.plugins[node.id.split("/", 1)[0]])
        storage.save_run(report)

    for group in plan.plugins.values():
        summarize_plugin(results, group, finished=True)
    report.status = "failed" if any(node.status == "failed" for node in report.nodes) else "succeeded"
    storage.save_run(report)


def add_plugin_results(report: RunReport, plan: ExecutionPlan) -> None:
    """Report rows for the nodes inside each plugin, right after the plugin node's own row."""
    if not plan.plugins:
        return
    known = {result.nodeId for result in report.nodes}
    by_id = {node.id: node for node in plan.nodes}
    rows = []
    for result in report.nodes:
        rows.append(result)
        group = plan.plugins.get(result.nodeId)
        if group is None:
            continue
        for inner_id in group.inner:
            if inner_id in known:
                continue
            inner = by_id[inner_id]
            label = inner.config.get("title") if inner.type == "custom" else None
            rows.append(NodeResult(nodeId=inner_id, type=inner.type, status="queued", label=label))
    report.nodes = rows


def summarize_plugin(results: dict[str, NodeResult], group: PluginGroup, finished: bool = False) -> None:
    """The plugin node's row on the canvas: status from its inner nodes, transfers from its input and output nodes."""
    result, inner = results[group.node.id], [results[node_id] for node_id in group.inner]
    statuses = {item.status for item in inner}
    if "failed" in statuses:
        result.status = "failed"
        result.error = next(item.error for item in inner if item.status == "failed")
    elif not finished:
        result.status = "running" if statuses & {"running", "succeeded", "skipped"} else "queued"
    else:
        result.status = "succeeded" if "succeeded" in statuses else "skipped"
    many_inputs, many_outputs = len(group.inputs) > 1, len(group.outputs) > 1
    result.inputs = [
        transfer.model_copy(update={"port": f"in{index}" if many_inputs else None})
        for index, node_id in sorted(group.inputs.items()) for transfer in results[node_id].inputs or []
    ]
    result.outputs = [
        transfer.model_copy(update={"port": f"out{index}" if many_outputs else None})
        for index, node_id in sorted(group.outputs.items()) for transfer in results[node_id].outputs or []
    ]
    findings = sum(len((item.output or {}).get("findings") or []) for item in inner if item.type in SCANNERS)
    result.output = {"innerNodes": len(inner), "findings": findings}
