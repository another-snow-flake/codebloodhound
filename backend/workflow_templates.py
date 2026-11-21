from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, field_validator

from .runner import plan_run, plugin_graph
from .schemas import ApiProblem, Identifier, Node, Workflow, WorkflowDraft


Tag = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=32, pattern=r"^[^\x00]+$")]


class TemplateMetadata(BaseModel):
    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100, pattern=r"^[^\x00]+$")]
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1200, pattern=r"^[^\x00]+$")]
    tags: list[Tag] = Field(default_factory=list, max_length=8)

    @field_validator("tags")
    @classmethod
    def distinct_tags(cls, tags: list[str]) -> list[str]:
        unique = {}
        for tag in tags:
            unique.setdefault(tag.casefold(), tag)
        return list(unique.values())


class PublishTemplate(TemplateMetadata):
    workflowId: Identifier


class TemplateSummary(TemplateMetadata):
    id: Identifier
    author: str
    updatedAt: datetime
    workflowId: Identifier | None = None


class PublicTemplate(TemplateSummary):
    draft: WorkflowDraft


def make_public_draft(workflow: Workflow, title: str) -> WorkflowDraft:
    if any(node.config.get("privatePluginOwner") for node in workflow.nodes):
        raise ApiProblem(422, "private_plugin_in_workflow", "Remove the private plugin node before publishing.")
    plan_run(workflow)
    return WorkflowDraft(name=title, nodes=_portable_nodes(workflow.nodes), edges=workflow.edges)


PORTABLE_CONFIGS = {
    "source": {"path"},
    "custom": {"title", "color", "inputs", "outputs", "scanner", "language"},
    "plugin": {"title", "color", "inputs", "outputs"},
    "plugin_input": {"index"},
    "plugin_output": {"index"},
}
CONDITIONS = {
    "severity": {"minSeverity"},
    "count": {"countMinSeverity", "comparison", "threshold"},
    "regex": {"field", "pattern"},
}


def _portable_nodes(nodes: list[Node]) -> list[Node]:
    """Keep only the settings a copy needs; notes, bound projects and recipients stay private.
    A plugin keeps its graph, cleaned by the same rules."""
    portable = []
    for node in nodes:
        allowed = PORTABLE_CONFIGS.get(node.type, set())
        if node.type == "trigger":
            allowed = {"mode"}
            if node.config.get("mode") == "daily":
                allowed |= {"scheduleTime", "scheduleTimezone"}
        elif node.type == "condition":
            allowed = {"conditionMode"} | CONDITIONS[node.config.get("conditionMode", "severity")]
        config = {key: value for key, value in node.config.items() if key in allowed}
        if node.type == "plugin":
            graph = plugin_graph(node)
            config["graph"] = {
                "nodes": [item.model_dump(mode="json") for item in _portable_nodes(graph.nodes)],
                "edges": [edge.model_dump(mode="json", exclude_none=True) for edge in graph.edges],
            }
        portable.append(node.model_copy(update={"config": config}))
    return portable
