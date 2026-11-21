import operator
from collections.abc import Collection

import re2
from pydantic import JsonValue

from .schemas import ApiProblem, Finding


SEVERITY_RANK = {severity: rank for rank, severity in enumerate(("low", "medium", "high", "critical"))}
COMPARISONS = {"eq": operator.eq, "ne": operator.ne, "lt": operator.lt, "le": operator.le, "gt": operator.gt, "ge": operator.ge}
REGEX_FIELDS = {"file", "ruleId", "message", "cve", "advisoryId"}
MAX_PATTERN_LENGTH = 160
REGEX_OPTIONS = re2.Options()
REGEX_OPTIONS.log_errors = False


def compile_pattern(pattern: JsonValue):
    if not isinstance(pattern, str) or not pattern.strip() or len(pattern) > MAX_PATTERN_LENGTH:
        raise ApiProblem(422, "invalid_condition_regex", "Provide a regular expression of 1–160 characters.")
    try:
        return re2.compile(pattern, options=REGEX_OPTIONS)
    except (re2.error, UnicodeError):
        raise ApiProblem(422, "invalid_condition_regex", "The regular expression is invalid or unsupported by RE2.") from None


def _severity(value: JsonValue) -> int:
    if not isinstance(value, str) or value not in SEVERITY_RANK:
        raise ApiProblem(422, "invalid_condition", "Select a valid minimum severity.")
    return SEVERITY_RANK[value]


def validate_condition(config: dict[str, JsonValue]) -> None:
    mode = config.get("conditionMode", "severity")
    if mode == "severity":
        _severity(config.get("minSeverity"))
    elif mode == "count":
        _severity(config.get("countMinSeverity", "low"))
        comparison, threshold = config.get("comparison"), config.get("threshold")
        if not isinstance(comparison, str) or comparison not in COMPARISONS or type(threshold) is not int or threshold < 0:
            raise ApiProblem(422, "invalid_condition", "Select a comparison and enter a nonnegative integer.")
    elif mode == "regex":
        field = config.get("field")
        if not isinstance(field, str) or field not in REGEX_FIELDS:
            raise ApiProblem(422, "invalid_condition", "Select a finding field for the regular expression.")
        compile_pattern(config.get("pattern"))
    else:
        raise ApiProblem(422, "invalid_condition", "Select a supported condition mode.")


def evaluate_condition(config: dict[str, JsonValue], findings: Collection[Finding]) -> dict[str, JsonValue]:
    mode = config.get("conditionMode", "severity")
    if mode == "regex":
        pattern = compile_pattern(config["pattern"])
        field = config["field"]
        matches = sum(
            pattern.search(value) is not None
            for finding in findings if (value := getattr(finding, field)) is not None
        )
        return {"mode": mode, "matched": matches > 0, "count": matches}
    minimum = config.get("countMinSeverity", "low") if mode == "count" else config["minSeverity"]
    rank = _severity(minimum)
    count = sum(SEVERITY_RANK[finding.severity] >= rank for finding in findings)
    if mode == "count":
        return {"mode": mode, "matched": COMPARISONS[config["comparison"]](count, config["threshold"]), "count": count}
    return {"matched": count > 0}
