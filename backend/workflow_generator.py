import json
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from .ai import ChatClient
from .llm import LlmError
from .runner import validate_edges
from .schedule import DAILY_TIME
from .schemas import ApiProblem, Edge, ModelChoice, Node, NodeType, Position, Severity, SourceHandle, WorkflowDraft


class WorkflowGenerationRequest(ModelChoice):
    description: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    timezone: Annotated[str, StringConstraints(min_length=1, max_length=100)] = "UTC"


class GenerationResult(BaseModel):
    draft: WorkflowDraft
    needsSource: bool
    needsRecipient: bool


class GeneratedCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    conditionMode: Literal["severity", "count", "regex"]
    minSeverity: Severity | None = None
    countMinSeverity: Severity | None = None
    comparison: Literal["eq", "ne", "lt", "le", "gt", "ge"] | None = None
    threshold: int | None = Field(default=None, ge=0)
    field: Literal["file", "ruleId", "message", "cve", "advisoryId"] | None = None
    pattern: str | None = Field(default=None, max_length=160)


class GeneratedIntent(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
    scanners: list[Literal["secrets", "sca", "sast"]] = Field(min_length=1, max_length=3)
    explain: bool = False
    condition: GeneratedCondition | None = None
    notification: Literal["always", "match", "no_match"] | None = None
    scheduleTime: str | None = Field(default=None, pattern=f"^{DAILY_TIME.pattern}$")
    scheduleTimezone: str | None = Field(default=None, min_length=1, max_length=100)


SYSTEM_PROMPT = """Создай черновик защитной проверки учебного ZIP для CodeBloodhound по описанию.
Верни только один JSON-объект. Не добавляй поля вне описанной схемы.
Поля:
- name: короткое название без URL, ключей, паролей и имён файлов.
- scanners: непустой массив из secrets (секреты), sca (зависимости), sast (статический анализ). Без повторов.
- explain: true, если запросили AI-рекомендации по результатам; иначе false.
- condition: null или одно из условий:
  {"conditionMode":"severity","minSeverity":"high"} (low, medium, high или critical),
  {"conditionMode":"count","countMinSeverity":"low","comparison":"ge","threshold":2}
  (операторы eq, ne, lt, le, gt, ge),
  {"conditionMode":"regex","field":"file","pattern":"[.]kt$"}
  (поля file, ruleId, message, cve, advisoryId).
- notification: null, "always", "match" (условие сработало) или "no_match" (условие не сработало).
  Условие обязательно для match и no_match. Получателя пользователь выбирает вручную.
- scheduleTime: null для ручного запуска или HH:MM для ежедневного запуска.
- scheduleTimezone: null для часового пояса редактора или имя IANA, только если пользователь указал пояс.
AI-рекомендации, если нужны, ставятся после сканеров и перед условием.
Если запрос не про защитную проверку учебного проекта или его смысл зависит
от неподдерживаемой операции или периодичности, верни {"unsupported":true}.
Для обычного запроса на проверку безопасности без указания анализаторов используй все три.
Не включай адреса получателей, идентификаторы источников и команды."""


def _check_timezone(name: str) -> None:
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ApiProblem(422, "invalid_schedule", "Enter a valid IANA time zone.") from None


def _build_draft(intent: GeneratedIntent, timezone: str) -> GenerationResult:
    if len(set(intent.scanners)) != len(intent.scanners):
        raise ValueError("Keep only one occurrence of each scanner.")
    if intent.notification in ("match", "no_match") and intent.condition is None:
        raise ValueError("Conditional notification requires a condition.")

    trigger = Node(id="n1", type="trigger", position=Position(x=40, y=70), config={"mode": "manual"})
    if intent.scheduleTime is not None:
        timezone = intent.scheduleTimezone or timezone
        _check_timezone(timezone)
        trigger.config = {"mode": "daily", "scheduleTime": intent.scheduleTime, "scheduleTimezone": timezone}

    draft = WorkflowDraft(name=intent.name, nodes=[trigger], edges=[])

    def append(
        kind: NodeType, source: Node, config: dict[str, JsonValue] | None = None, handle: SourceHandle | None = None,
    ) -> Node:
        index = len(draft.nodes)
        node = Node(
            id=f"n{index + 1}", type=kind, config=config or {},
            position=Position(x=40 + index % 3 * 240, y=70 + index // 3 * 145),
        )
        draft.nodes.append(node)
        draft.edges.append(Edge(id=f"e{index}", source=source.id, target=node.id, sourceHandle=handle))
        return node

    end = trigger
    for scanner in intent.scanners:
        end = append(scanner, end)
    if intent.explain:
        end = append("ai", end)
    if intent.condition is not None:
        condition = append("condition", end, intent.condition.model_dump(exclude_none=True))
        if intent.notification in ("match", "no_match"):
            append("notify", condition, handle="true" if intent.notification == "match" else "false")
    if intent.notification == "always":
        append("notify", end)

    validate_edges(draft)
    return GenerationResult(
        draft=draft, needsSource=intent.scheduleTime is not None,
        needsRecipient=intent.notification is not None,
    )


def generate_workflow(request: WorkflowGenerationRequest, client: ChatClient) -> GenerationResult:
    _check_timezone(request.timezone)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": request.description},
    ]
    for attempt in range(2):
        try:
            response = client.complete(messages, json_mode=True, max_tokens=1024)
            value = json.loads(response)
            if isinstance(value, dict) and len(value) == 1 and value.get("unsupported") is True:
                raise ApiProblem(422, "unsupported_generation", "Describe a workflow using the supported security checks.")
            return _build_draft(GeneratedIntent.model_validate(value), request.timezone)
        except ApiProblem as error:
            if error.code == "unsupported_generation":
                raise
        except LlmError as error:
            if error.code not in ("invalid_response", "incomplete_response"):
                raise
        except ValueError:
            pass
        if attempt == 0:
            messages.append({"role": "user", "content": "Исправь формат и поля по схеме. Верни один полный JSON-объект."})
    raise LlmError("invalid_response", "The model could not produce a valid workflow draft.")
