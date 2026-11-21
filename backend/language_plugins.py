import ast
import re
from collections.abc import Iterator, Sequence

from .kotlin_text import without_comments


LANGUAGE_SUFFIXES = {
    "python": frozenset({".py"}),
    "javascript": frozenset({".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}),
}

RULE_MESSAGES = {
    "python-dynamic-code": "Avoid evaluating untrusted input as Python code.",
    "python-shell": "Prefer explicit arguments and avoid passing untrusted input to a shell.",
    "python-pickle": "Deserialize trusted data only. Use a data-only format for external input.",
    "js-dynamic-code": "Avoid evaluating untrusted input as JavaScript code.",
    "js-html-assignment": "Prefer textContent or sanitize HTML from untrusted input.",
}
JS_RULES = {
    "js-dynamic-code": re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()"),
    "js-html-assignment": re.compile(r"\.(?:innerHTML|outerHTML)\s*=(?!=|>)"),
}
JS_STRING = re.compile(r'''"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|`(?:\\.|[^`\\$]|\$(?!\{))*`''', re.S)


def active_suffixes(plugins: Sequence[str]) -> frozenset[str]:
    return frozenset(suffix for plugin in plugins for suffix in LANGUAGE_SUFFIXES[plugin])


def python_issues(source: str) -> Iterator[tuple[str, int]]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, RecursionError, ValueError):
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            yield "python-dynamic-code", node.lineno
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            continue
        if func.value.id == "pickle" and func.attr in {"load", "loads"}:
            yield "python-pickle", node.lineno
        if func.value.id == "subprocess" and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            yield "python-shell", node.lineno


def javascript_issues(source: str) -> Iterator[tuple[str, int]]:
    code = JS_STRING.sub(lambda match: re.sub(r"[^\r\n]", " ", match[0]), without_comments(source))
    for line, text in enumerate(code.splitlines(), start=1):
        for rule, pattern in JS_RULES.items():
            if pattern.search(text):
                yield rule, line
