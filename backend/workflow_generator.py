import json
import re
from typing import Annotated, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints

from .ai import ChatClient
from .conditions import compile_pattern
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
    usedRules: bool = False


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
                       r"порог|количеств|число\s+находок|регуляр|regex|выражени|если\s+(?:есть|будут|найд|обнаруж)|\bif\b", re.I)
EXCLUDED = re.compile(r"(?:\bбез\b|\bне\s+(?:добавляй|добавлять|запускай|включай|включать|используй)\b"
                      r"|\b(?:without|exclude|skip|do not (?:add|run|include|use))\b)[^.!?;\n]*?"
                      r"(?=[.!?;\n]|,\s*(?:затем|потом|добавь|запусти|проверь|then|include)\b|$)", re.I)
SCHEDULE = re.compile(r"кажд\w* (?:день|сутки|утро|вечер)|ежедневн|\bdaily\b|\bevery day\b", re.I)
MANUAL = re.compile(r"ручн\w*|вручную|\bmanual(?:ly)?\b|\bno schedule\b", re.I)
NO_SCHEDULE = re.compile(r"\bбез\s+расписания\b|\bwithout(?: a)? schedule\b", re.I)
SCHEDULE_TIME = re.compile(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b")
ZONE = re.compile(r"\b[A-Z][A-Za-z_]+/[A-Z][A-Za-z_]+(?:/[A-Z][A-Za-z_]+)?\b|\bUTC\b")
MOSCOW_TIME = re.compile(r"\bпо\s+(?:москве|московскому\s+времени)\b|\bмск\b|\bmoscow time\b", re.I)
EXPLICIT_SCOPE = re.compile(
    r"""(?:\bтолько\s+в\s+(?:файле|папке|каталоге)\s+|\bonly\s+in\s+(?:the\s+)?(?:file|folder|directory)\s+)"""
    r"""(?:["«`]([^"»`\r\n]+)["»`]|([\w./-]+))""", re.I,
)
EXPLICIT_REGEX = re.compile(
    r"""\b(?:регулярн\w+\s+выражени\w+|регулярк\w*|regex)\s*:?\s*"""
    r"""(?P<literal>\x60[^\x60\r\n]*\x60|«[^»\r\n]*»|"[^"\r\n]*")""", re.I,
)
REGEX_NO_MATCH = re.compile(
    r"\bесли\s+(?:нет\s+совпадени\w*|[^.!?;\r\n]{0,100}?\bне\s+(?:совп\w*|соответству\w*))"
    r"|\bif\s+(?:no\s+matches\b|no\s+(?:paths?|files?|findings?)\s+matches?\b|"
    r"[^.!?;\r\n]{0,100}?\b(?:does not|do not|doesn't|don't)\s+match\b)"
    r"|\bunless\s+[^.!?;\r\n]{0,100}?\bmatches?\b", re.I,
)
REGEX_MATCH = re.compile(
    r"\bесли\s+[^.!?;\r\n]{0,100}?\bсовп(?:ал\w*|ада\w*|ад\w*)"
    r"|\bif\s+[^.!?;\r\n]{0,100}?\bmatches?\b", re.I,
)
COUNT_COMPARISON = {
    "больше": "gt", "меньше": "lt", "равно": "eq", "ровно": "eq", "не равно": "ne",
    "не менее": "ge", "не более": "le", "больше или равно": "ge", "меньше или равно": "le",
}
COUNT_REQUEST = re.compile(
    r"(?:число|количество)\s+находок\s*[:—-]?\s*("
    + "|".join(sorted(COUNT_COMPARISON, key=len, reverse=True)) + r")\s+(\d+)\b", re.I,
)
CONDITIONAL = re.compile(r"\b(?:если|if|unless)\b", re.I)
SEVERITY_WORDS = {
    "critical": re.compile(r"критическ\w*|\bcritical\b", re.I),
    "high": re.compile(r"высок\w*|\bhigh\b", re.I),
    "medium": re.compile(r"средн\w*|\bmedium\b", re.I),
    "low": re.compile(r"низк\w*|\blow\b", re.I),
}
NON_DAILY = re.compile(r"еженедел|ежемесяч|по будням|по выходным|раз в неделю|кажд\w* недел|\bweekly\b|\bmonthly\b", re.I)


def _align_with_description(value: dict, description: str, regex: re.Match[str] | None) -> dict:
    """Drop parts of the model's answer that the user did not ask for."""
    value = dict(value)
    if regex is not None:
        condition = value.get("condition")
        if not isinstance(condition, dict) or condition.get("conditionMode") != "regex":
            raise ValueError("Use a regex condition for the quoted regular expression.")
        value["condition"] = {**condition, "pattern": regex["literal"][1:-1]}
        start, end = regex.span("literal")
        description = description[:start] + " " + description[end:]
    scope = EXPLICIT_SCOPE.search(description)
    path = value.get("scanPath")
    if scope:
        value["scanPath"] = (scope[1] or scope[2].rstrip(".")) or None
    elif isinstance(path, str) and (path in {".", "./", "/", "*", "**"} or not re.search(
        r"(?<![\w./-])" + re.escape(path) + r"(?![\w/-]|\.[\w.])", description
    )):
        value["scanPath"] = None
    count = COUNT_REQUEST.search(description)
    if count:
        previous = value.get("condition")
        severity = previous.get("countMinSeverity") if isinstance(previous, dict) else None
        value["condition"] = {"conditionMode": "count", "comparison": COUNT_COMPARISON[count[1].lower()],
                              "threshold": int(count[2]), "countMinSeverity": severity or "low"}
    excluded = " ".join(match[0] for match in EXCLUDED.finditer(description))
    requested = EXCLUDED.sub(" ", description)
    mentions = [(match.start(), kind) for kind, pattern in MENTIONS.items() if (match := pattern.search(requested))]
    scanners = value.get("scanners")
    if isinstance(scanners, list) and all(isinstance(scanner, str) for scanner in scanners):
        denied = {kind for kind, pattern in MENTIONS.items() if pattern.search(excluded)}
        selected = [kind for _, kind in sorted(mentions)] if mentions else scanners
        value["scanners"] = [kind for kind in selected if kind not in denied]
    wants_notification = bool(NOTIFY.search(requested))
    if not wants_notification:
        value["notification"] = None
    if not EXPLAIN.search(requested):
        value["explain"] = False
    if value.get("condition") is not None and not CONDITION.search(description):
        value["condition"] = None
    condition = value.get("condition")
    if wants_notification and isinstance(condition, dict) and condition.get("conditionMode") == "regex":
        if REGEX_NO_MATCH.search(requested):
            value["notification"] = "no_match"
        elif REGEX_MATCH.search(requested):
            value["notification"] = "match"
    notification = value.get("notification")
    if wants_notification and CONDITION.search(requested) and CONDITIONAL.search(requested):
        if notification not in ("match", "no_match") or value.get("condition") is None:
            raise ValueError("Use the requested condition and connect the notification to its match or no_match branch.")
    if notification in ("match", "no_match") and value.get("condition") is None:
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
    regex = EXPLICIT_REGEX.search(request.description)
    if regex is not None:
        compile_pattern(regex["literal"][1:-1])
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
            return _build_draft(
                GeneratedIntent.model_validate(_align_with_description(value, request.description, regex)), request.timezone
            )
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


def generate_workflow_without_model(request: WorkflowGenerationRequest) -> GenerationResult:
    """Build a draft only for the instructions the local rules can recognize."""
    description = request.description
    regex = EXPLICIT_REGEX.search(description)
    prose = description
    if regex is not None:
        compile_pattern(regex["literal"][1:-1])
        start, end = regex.span("literal")
        prose = description[:start] + " " + description[end:]
    requested = EXCLUDED.sub(" ", prose)
    unsupported = ApiProblem(422, "unsupported_generation", "Describe a supported scan and give any condition explicitly.")
    if NON_DAILY.search(requested):
        raise unsupported
    if not any(pattern.search(requested) for pattern in MENTIONS.values()) and not re.search(
        r"(?:проверь|сканируй|проверка|scan|check)\s+(?:учебн\w*\s+)?(?:проект\w*|архив\w*|zip|project|archive)", requested, re.I,
    ):
        raise unsupported
    conditional = bool(CONDITIONAL.search(requested))
    severity = next((key for key, pattern in SEVERITY_WORDS.items() if pattern.search(requested)), None)
    condition: dict | None = None
    negative = bool(re.search(r"\bесли\s+нет\b|\bif\s+(?:there (?:are|is) )?no\b|\bunless\b", requested, re.I))
    if regex is not None:
        field = re.search(r"\b(file|ruleId|message|cve|advisoryId)\b", requested)
        condition = {"conditionMode": "regex", "field": field[1] if field else "file"}
        negative = negative or bool(REGEX_NO_MATCH.search(requested))
    elif COUNT_REQUEST.search(requested):
        condition = {"conditionMode": "count", "countMinSeverity": severity or "low"}
    elif conditional and severity:
        condition = {"conditionMode": "severity", "minSeverity": severity}
    elif conditional or re.search(r"регуляр|regex|порог|число\s+находок|количество\s+находок", requested, re.I):
        raise unsupported

    notification = None
    if NOTIFY.search(requested):
        notification = ("no_match" if negative else "match") if condition is not None else "always"
    raw = {
        "name": "Проверка учебного проекта", "scanners": list(MENTIONS),
        "condition": condition, "notification": notification, "explain": bool(EXPLAIN.search(requested)),
    }
    try:
        intent = GeneratedIntent.model_validate(_align_with_description(raw, description, regex))
    except ValueError:
        raise unsupported from None
    return _build_draft(intent, request.timezone).model_copy(update={"usedRules": True})
