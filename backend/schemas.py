from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, JsonValue, StringConstraints


Identifier = Annotated[str, StringConstraints(min_length=1, max_length=100)]
NodeType = Literal["trigger", "source", "secrets", "sca", "sast", "condition", "ai", "notify", "custom"]
LanguagePlugin = Literal["python", "javascript"]
# condition edges leave through "true"/"false"; a custom node with several outputs or inputs
# names the port: "out1".."out4", "in1".."in4"
SourceHandle = Annotated[str, StringConstraints(pattern=r"^(?:true|false|out[1-4])$")]
TargetHandle = Annotated[str, StringConstraints(pattern=r"^(?:in[1-4]|source)$")]
RunStatus = Literal["queued", "running", "succeeded", "failed"]
TriggerMode = Literal["manual", "daily"]
NodeStatus = Literal["queued", "running", "succeeded", "failed", "skipped"]
Severity = Literal["low", "medium", "high", "critical"]


class Position(BaseModel):
    x: float = Field(allow_inf_nan=False)
    y: float = Field(allow_inf_nan=False)


class Node(BaseModel):
    id: Identifier
    type: NodeType
    position: Position
    config: dict[str, JsonValue] = Field(default_factory=dict)


class Edge(BaseModel):
    id: Identifier
    source: Identifier
    target: Identifier
    sourceHandle: SourceHandle | None = None
    targetHandle: TargetHandle | None = None


class WorkflowDraft(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=150)]
    nodes: list[Node] = Field(max_length=100)
    edges: list[Edge] = Field(max_length=300)


class Workflow(WorkflowDraft):
    id: Identifier
    languagePlugins: list[LanguagePlugin] | None = None


class NodeTemplateDraft(BaseModel):
    """A node saved to the shared library: a custom node or a standard one with its text."""
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=60)]
    type: NodeType
    config: dict[str, JsonValue] = Field(default_factory=dict)


class NodeTemplate(NodeTemplateDraft):
    id: Identifier


class SourceCreated(BaseModel):
    sourceId: Identifier


class RepositorySourceRequest(BaseModel):
    url: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]


ModelId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class ModelChoice(BaseModel):
    """Model for one request. None means the server environment's model.
    allowExternal is the user's consent to send findings to an external provider."""
    modelId: ModelId | None = None
    allowExternal: bool = False


class RunRequest(ModelChoice):
    sourceId: Identifier


class RunCreated(BaseModel):
    runId: Identifier
    status: RunStatus


class Finding(BaseModel):
    id: Identifier
    scanner: Literal["secrets", "sca", "sast"]
    ruleId: str
    file: str
    line: int | None = Field(ge=1)
    severity: Severity
    message: str
    cve: str | None = None
    advisoryId: str | None = None
    group: str | None = None
    artifact: str | None = None
    version: str | None = None
    secretClass: str | None = None


class Recommendation(BaseModel):
    findingId: Identifier
    explanation: str
    remediation: str


class AiGroup(BaseModel):
    """Findings that share one fix, e.g. several CVEs closed by one dependency update."""
    id: Identifier
    title: str
    action: str
    explanation: str
    severity: Severity
    rationale: str
    findingIds: list[Identifier]
    source: Literal["model", "template"] = "model"  # template: the model skipped this group or was not asked


class AiPriority(BaseModel):
    groupId: Identifier
    action: str


class AiAnalysis(BaseModel):
    summary: str
    recommendations: list[Recommendation]
    priorities: list[AiPriority] = Field(default_factory=list)
    groups: list[AiGroup] = Field(default_factory=list)
    source: Literal["model", "template"] = "model"  # template: built from scanner rules without the model


ChatText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: ChatText


class RunChatRequest(ModelChoice):
    question: ChatText
    history: list[ChatTurn] = Field(default_factory=list, max_length=8)


class RunChatResponse(BaseModel):
    answer: str
    model: str | None = None


class LlmOptionOut(BaseModel):
    id: str
    provider: Literal["local", "deepseek"]
    model: str
    available: bool
    reason: Literal["connection_error", "model_missing", "no_api_key"] | None = None


class LlmSettings(BaseModel):
    defaultId: str | None
    options: list[LlmOptionOut]


class LlmCheckRequest(ModelChoice):
    modelId: ModelId


class LlmCheckResult(BaseModel):
    modelId: str
    ok: bool
    seconds: float | None = None
    code: str | None = None
    message: str | None = None


class NodeTransfer(BaseModel):
    nodeId: Identifier | None = None
    port: str | None = None
    findingCount: int
    analysisCount: int
    findingIds: list[Identifier]
    analysisNodeIds: list[Identifier]
    sourcePath: str | None = None


class NodeResult(BaseModel):
    nodeId: Identifier
    label: str | None = None
    type: NodeType | None = None
    status: NodeStatus = "queued"
    output: dict[str, JsonValue] | None = None
    error: str | None = None
    inputs: list[NodeTransfer] | None = None
    outputs: list[NodeTransfer] | None = None


class RunReport(BaseModel):
    runId: Identifier
    workflowId: Identifier
    createdAt: datetime | None = None
    triggerMode: TriggerMode = "manual"
    scheduledFor: datetime | None = None
    status: RunStatus = "queued"
    nodes: list[NodeResult]
    findings: list[Finding] = Field(default_factory=list)
    aiAnalysis: AiAnalysis | None = None
    languagePlugins: list[LanguagePlugin] | None = None

    @classmethod
    def for_workflow(cls, workflow: Workflow, scheduled_for: datetime | None = None) -> "RunReport":
        return cls(
            runId=uuid4().hex,
            workflowId=workflow.id,
            createdAt=datetime.now(timezone.utc),
            scheduledFor=scheduled_for,
            triggerMode="daily" if scheduled_for is not None else "manual",
            languagePlugins=workflow.languagePlugins,
            status="queued",
            nodes=[
                NodeResult(
                    nodeId=node.id, type=node.type, status="queued",
                    label=node.config["title"] if node.type == "custom" else None,
                )
                for node in workflow.nodes
            ],
            findings=[],
        )


class RunListItem(BaseModel):
    runId: Identifier
    status: RunStatus
    createdAt: datetime | None = None
    triggerMode: TriggerMode = "manual"
    findingCount: int = Field(ge=0)


class ApiProblem(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
