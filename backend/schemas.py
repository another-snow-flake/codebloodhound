from typing import Annotated, Literal

from pydantic import BaseModel, Field, JsonValue, StringConstraints


Identifier = Annotated[str, StringConstraints(min_length=1, max_length=100)]
NodeType = Literal["trigger", "secrets", "sca", "sast", "condition", "ai", "notify"]
RunStatus = Literal["queued", "running", "succeeded", "failed"]
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
    sourceHandle: Literal["true", "false"] | None = None


class WorkflowDraft(BaseModel):
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=150)]
    nodes: list[Node] = Field(max_length=100)
    edges: list[Edge] = Field(max_length=300)


class Workflow(WorkflowDraft):
    id: Identifier


class SourceCreated(BaseModel):
    sourceId: Identifier


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


class NodeResult(BaseModel):
    nodeId: Identifier
    status: NodeStatus = "queued"
    output: dict[str, JsonValue] | None = None
    error: str | None = None


class RunReport(BaseModel):
    runId: Identifier
    workflowId: Identifier
    status: RunStatus = "queued"
    nodes: list[NodeResult]
    findings: list[Finding] = Field(default_factory=list)
    aiAnalysis: AiAnalysis | None = None


class ApiProblem(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
