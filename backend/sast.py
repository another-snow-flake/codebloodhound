import itertools
import re
from collections.abc import Iterator
from uuid import uuid4

from .kotlin_text import without_comments
from .schemas import Finding, Severity
from .sources import read_project_text


STRING = r'(?:"""[\s\S]*?"""|"(?:\\.|[^"\\\r\n])*")'
QUERY = r"\.(?:queryForList|queryForObject|queryForMap|query|update|execute)\s*\(\s*"
DIRECT_SQL = re.compile(rf"{QUERY}(?P<sql>{STRING})(?P<concat>\s*\+)?")
NAMED_SQL = re.compile(
    rf"\b(?:val|var)\s+(?P<name>[A-Za-z_]\w*)(?:\s*:\s*String)?\s*=\s*(?P<sql>{STRING})(?P<concat>\s*\+)?"
)
SQL_COMMAND = re.compile(r'^\s*"+\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b', re.I)
INTERPOLATION = re.compile(r"(?<!\\)\$(?:[A-Za-z_]\w*|\{)")
INSECURE_TLS = re.compile(
    r"\bHostnameVerifier\s*\{\s*(?:[^{}\n]{1,120}->\s*)?true\s*\}"
    r"|\bNoopHostnameVerifier\s*(?:\.\s*INSTANCE\b|\()"
)
CORS_BLOCK = re.compile(r"\bCorsConfiguration\s*\(\s*\)\s*\.apply\s*\{([^{}]*)\}")
WILDCARD_ORIGIN = re.compile(
    r'\b(?:allowedOrigins|allowedOriginPatterns)\s*=\s*(?:listOf|mutableListOf)\s*\([^)]*"\*"'
    r'|\baddAllowedOrigin(?:Pattern)?\s*\(\s*"\*"\s*\)'
)
CREDENTIALS = re.compile(r"\ballowCredentials\s*=\s*true\b|\bsetAllowCredentials\s*\(\s*true\s*\)")
ROUTE = re.compile(
    r'\brequestMatchers\s*\(\s*(?:(?:HttpMethod\.)?([A-Z]+)\s*,\s*)?'
    r'"(/[^"\r\n]*)"\s*\)\s*\.\s*(permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority|denyAll)\s*\('
)
MAX_ROUTES = 300
OWNER_COLUMN = r"\b(?:owner|user|customer|account|tenant)_id\b"
OWNER_FIELD = re.compile(OWNER_COLUMN, re.I)
LOOKUP_BY_ID = re.compile(r"\b(?:\w+_)?id\s*=\s*(?:\?|:\w+)", re.I)
SELECT_WHERE = re.compile(r"\bSELECT\s+(.+?)\s+FROM\b.+?\bWHERE\s+(.+)", re.I | re.S)

RULES: dict[str, tuple[Severity, str]] = {
    "sql-injection": (
        "high", "SQL text includes a value assembled in code. Bind values as query parameters.",
    ),
    "tls-verification": (
        "medium", "The HTTPS client accepts a hostname without checking it. Use the default TLS hostname verifier.",
    ),
    "credentialed-cors": (
        "medium", "A CORS configuration permits credentials for arbitrary origins. List trusted origins explicitly.",
    ),
    "route-authorization": (
        "high", "A public route is declared before a restricted rule that also covers it. Check matcher order and access.",
    ),
    "object-authorization": (
        "high", "A record with an owner is looked up by ID alone. Verify ownership in the lookup or its caller.",
    ),
}


def sql_issues(code: str) -> Iterator[tuple[str, int]]:
    for match in DIRECT_SQL.finditer(code):
        sql = match["sql"]
        if SQL_COMMAND.match(sql) and (INTERPOLATION.search(sql) or match["concat"]):
            yield "sql-injection", match.start("sql")
        if parts := SELECT_WHERE.search(sql):
            columns, predicate = parts.groups()
            if OWNER_FIELD.search(columns) and LOOKUP_BY_ID.search(predicate) and not OWNER_FIELD.search(predicate):
                yield "object-authorization", match.start("sql")

    for match in NAMED_SQL.finditer(code):
        sql = match["sql"]
        if not SQL_COMMAND.match(sql) or not (INTERPOLATION.search(sql) or match["concat"]):
            continue
        call = re.compile(rf"{QUERY}{re.escape(match['name'])}\s*[,)]")
        # Limit tracking to a nearby use before the next Kotlin function.
        scope = re.split(r"\bfun\b", code[match.end():match.end() + 1000], maxsplit=1)[0]
        if call.search(scope):
            yield "sql-injection", match.start("sql")


def kotlin_issues(code: str) -> Iterator[tuple[str, int]]:
    yield from sql_issues(code)
    for match in INSECURE_TLS.finditer(code):
        yield "tls-verification", match.start()
    for match in CORS_BLOCK.finditer(code):
        options = match[1]
        origin = WILDCARD_ORIGIN.search(options)
        if origin and CREDENTIALS.search(options):
            yield "credentialed-cors", match.start(1) + origin.start()
    # each public route is compared with the rules after it; real configs have dozens of rules,
    # and the cap keeps a crafted file with thousands of them from tying up the scanner
    routes = list(itertools.islice(ROUTE.finditer(code), MAX_ROUTES))
    for index, route in enumerate(routes):
        method, path, access = route.groups()
        if access != "permitAll":
            continue
        for restricted in routes[index + 1:]:
            restricted_method, pattern, rule = restricted.groups()
            prefix = pattern.removesuffix("/**")
            if (
                rule != "permitAll" and pattern.endswith("/**")
                and (not method or not restricted_method or method == restricted_method)
                and (path == prefix or path.startswith(prefix + "/"))
            ):
                yield "route-authorization", route.start()
                break


def find_kotlin_issues(data: bytes) -> list[Finding]:
    findings = []
    for path, content in read_project_text(data, lambda candidate: candidate.suffix.lower() == ".kt"):
        code = without_comments(content)
        issues = {(rule, code.count("\n", 0, offset) + 1) for rule, offset in kotlin_issues(code)}
        for rule, line in sorted(issues, key=lambda item: (item[1], item[0])):
            severity, message = RULES[rule]
            findings.append(Finding(
                id=uuid4().hex, scanner="sast", ruleId=rule, file=path.as_posix(),
                line=line, severity=severity, message=message,
            ))
    return findings
