import json
import re
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
    scanPath: str | None = Field(default=None, min_length=1, max_length=500)


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
- scanPath: null для целого проекта либо один относительный путь в ZIP, если его явно указали для всех сканеров.
AI-рекомендации, если нужны, ставятся после сканеров и перед условием.
Если запрос не про защитную проверку учебного проекта или его смысл зависит
от неподдерживаемой операции или периодичности, верни {"unsupported":true}.
Для обычного запроса на проверку безопасности без указания анализаторов используй все три.
Не включай адреса получателей, идентификаторы источников и команды."""


# Small models add what nobody asked for: every scanner, a notification, a schedule in another time zone.
# The draft keeps only what the description mentions; the model still decides the rest of the structure.
MENTIONS = {
    "secrets": re.compile(r"секрет|парол|токен|ключ|secret|credential|password|token", re.I),
    "sca": re.compile(r"зависимост|библиотек|пакет|\bcve\b|\bsca\b|dependenc", re.I),
    "sast": re.compile(r"\bsast\b|статическ|static|опасн\w* код|инъекц|injection|\bsql\b", re.I),
}
NOTIFY = re.compile(r"уведом|оповещ|сообщ|отправ|webhook|вебхук|notify|notification|алерт|alert", re.I)
EXPLAIN = re.compile(r"\bai\b|\bии\b|рекоменд|объясн|совет|нейросет|explain|recommend", re.I)
CONDITION = re.compile(r"критич|severity|high|critical|medium|низк|средн|высок|больше|меньше|не менее|не более|хотя бы|"
                       r"порог|количеств|регуляр|regex|выражени|если\s+(?:есть|будут|найд|обнаруж)|\bif\b", re.I)
EXCLUDED = re.compile(r"(?:\bбез\b|\bне\s+(?:добавляй|добавлять|запускай|включай|включать|используй)\b"
                      r"|\b(?:without|exclude|skip|do not (?:add|run|include|use))\b)[^.!?;\n]*?"
                      r"(?=[.!?;\n]|,\s*(?:затем|потом|добавь|запусти|проверь|then|include)\b|$)", re.I)
SCHEDULE = re.compile(r"кажд\w* (?:день|сутки|утро|вечер)|ежедневн|\bdaily\b|\bevery day\b", re.I)
MANUAL = re.compile(r"ручн\w*|вручную|\bmanual(?:ly)?\b|\bno schedule\b", re.I)
NO_SCHEDULE = re.compile(r"\bбез\s+расписания\b|\bwithout(?: a)? schedule\b", re.I)
SCHEDULE_TIME = re.compile(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b")
ZONE = re.compile(r"\b[A-Z][A-Za-z_]+/[A-Z][A-Za-z_]+(?:/[A-Z][A-Za-z_]+)?\b|\bUTC\b")
MOSCOW_TIME = re.compile(r"\bпо\s+(?:москве|московскому\s+времени)\b|\bмск\b|\bmoscow time\b", re.I)


def _align_with_description(value: dict, description: str) -> dict:
    """Drop parts of the model's answer that the user did not ask for."""
    value = dict(value)
    path = value.get("scanPath")
    if isinstance(path, str) and (path in {".", "./", "/", "*", "**"} or not re.search(r"(?<![\w./-])" + re.escape(path) + r"(?![\w/-])", description)):
        value["scanPath"] = None
    count = re.search(
        r"(?:число|количество)\s+находок\s*[:—-]?\s*"
        r"(больше или равно|меньше или равно|не менее|не более|больше|меньше|равно)\s+(\d+)\b",
        description, re.I,
    )
    if count:
        operators = {"больше": "gt", "меньше": "lt", "равно": "eq", "не менее": "ge",
                     "не более": "le", "больше или равно": "ge", "меньше или равно": "le"}
        previous = value.get("condition")
        severity = previous.get("countMinSeverity") if isinstance(previous, dict) else None
        value["condition"] = {"conditionMode": "count", "comparison": operators[count[1].lower()],
                              "threshold": int(count[2]), "countMinSeverity": severity or "low"}
    excluded = " ".join(match[0] for match in EXCLUDED.finditer(description))
    requested = EXCLUDED.sub(" ", description)
    mentions = [(match.start(), kind) for kind, pattern in MENTIONS.items() if (match := pattern.search(requested))]
    scanners = value.get("scanners")
    if isinstance(scanners, list) and all(isinstance(scanner, str) for scanner in scanners):
        denied = {kind for kind, pattern in MENTIONS.items() if pattern.search(excluded)}
        selected = [kind for _, kind in sorted(mentions)] if mentions else scanners
        value["scanners"] = [kind for kind in selected if kind not in denied]
    if not NOTIFY.search(requested):
        value["notification"] = None
    if not EXPLAIN.search(requested):
        value["explain"] = False
    if value.get("condition") is not None and not CONDITION.search(description):
        value["condition"] = None
    if value.get("notification") in ("match", "no_match") and value.get("condition") is None:
        value["notification"] = "always"
    if MANUAL.search(requested) or NO_SCHEDULE.search(description) or not SCHEDULE.search(requested):
        value["scheduleTime"] = None
        value["scheduleTimezone"] = None
    else:
        time = SCHEDULE_TIME.search(requested)
        value["scheduleTime"] = f"{int(time.group(1)):02d}:{time.group(2)}" if time else value.get("scheduleTime") or "09:00"
        zone = ZONE.search(requested)
        value["scheduleTimezone"] = zone[0] if zone else "Europe/Moscow" if MOSCOW_TIME.search(requested) else None
    return value


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
        kind: NodeType, source: Node | None, config: dict[str, JsonValue] | None = None, handle: SourceHandle | None = None,
    ) -> Node:
        index = len(draft.nodes)
        node = Node(
            id=f"n{index + 1}", type=kind, config=config or {},
            position=Position(x=40 + index % 3 * 240, y=70 + index // 3 * 145),
        )
        draft.nodes.append(node)
        if source is not None:
            draft.edges.append(Edge(id=f"e{index}", source=source.id, target=node.id, sourceHandle=handle))
        return node

    end = trigger
    for scanner in intent.scanners:
        end = append(scanner, end)
    if intent.scanPath is not None:
        scopes = [node for node in draft.nodes if node.type in intent.scanners]
        source_node = append("source", None, {"path": intent.scanPath})
        draft.edges.extend(
            Edge(id=f"scope-{node.id}", source=source_node.id, target=node.id, targetHandle="source")
            for node in scopes
        )
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
            if not isinstance(value, dict):
                raise ValueError("The answer must be one JSON object.")
            return _build_draft(GeneratedIntent.model_validate(_align_with_description(value, request.description)), request.timezone)
        except ApiProblem as error:
            if error.code == "unsupported_generation":
                raise
            problem = str(error)[:300]
        except LlmError as error:
            if error.code not in ("invalid_response", "incomplete_response"):
                raise
            problem = "ответ не является корректным JSON-объектом"
        except ValueError as error:
            problem = str(error).splitlines()[0][:300]
        if attempt == 0:
            # tell the model what was wrong: a bare "fix it" made it repeat the same answer
            messages.append({"role": "user", "content": f"Ответ отклонён: {problem}. Исправь по схеме и верни один полный JSON-объект."})
    raise LlmError("invalid_response", "The model could not produce a valid workflow draft.")
