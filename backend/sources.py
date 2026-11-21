import io
import re
import stat
from collections.abc import Callable, Iterator, Sequence
from pathlib import PurePosixPath
from posixpath import commonpath
from uuid import uuid4
from zipfile import BadZipFile, ZipFile
from zlib import error as ZipDecodeError

from .language_plugins import active_suffixes
from .schemas import ApiProblem, Finding


MAX_UPLOAD = 10 * 1024 * 1024
MAX_PROJECT_SIZE = 40 * 1024 * 1024
MAX_FILES = 2000
MAX_TEXT_FILE = 1024 * 1024
TEXT_SUFFIXES = {".kt", ".kts", ".java", ".properties", ".yml", ".yaml", ".json", ".toml", ".env"}
CODE_SUFFIXES = {".kt", ".kts", ".java"}
GRADLE_FILES = {"settings.gradle.kts", "settings.gradle", "build.gradle.kts", "build.gradle", "gradle.lockfile"}
JS_DECLARATION = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+")
PYTHON_ANNOTATION = re.compile(r"^(\s*[\w.-]+)\s*:\s*str\s*=")
SECRET_KEY = r"[\w.-]*(?:password|passwd|secret|token|api[-_.]?key)"
SECRET_ASSIGNMENT = re.compile(
    rf'''(?ix)^\s*(?:(?:export|(?:(?:private|protected|internal|public|override|const)\s+)*(?:val|var))\s+)?
    ["']?(?P<key>{SECRET_KEY})["']?
    \s*(?::\s*String\??\s*=|[:=])\s*(?P<value>[^\s#,]+)'''
)
AUTHORIZATION_VALUE = re.compile(r'''(?i)^\s*["']?authorization["']?\s*[:=]\s*["']?(?:Bearer|Basic)\s+([^\s"'#,]+)''')
KOTLIN_STRING = r'"(?:[^"\\$]|\\.)+"'
KOTLIN_ENV_FALLBACK = re.compile(
    rf'''\bSystem\.getenv\(\s*"(?i:{SECRET_KEY})"\s*\)\s*\?:\s*{KOTLIN_STRING}\s*(?://.*)?$'''
)
KOTLIN_LOCAL = re.compile(r"^\s*(?:val|var)\s+([a-zA-Z_]\w*)\s*=\s*(.*?)\s*$")
KOTLIN_CONCAT = re.compile(r"[a-zA-Z_]\w*(?:\s*\+\s*[a-zA-Z_]\w*)+")
KOTLIN_BEARER = re.compile(r"\bsetBearerAuth\(\s*([a-zA-Z_]\w*)\s*\)")


def validate_zip(data: bytes) -> None:
    try:
        with ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_FILES or sum(entry.file_size for entry in entries) > MAX_PROJECT_SIZE:
                raise ApiProblem(413, "project_too_large", "The ZIP exceeds the file count or unpacked size limit.")
            seen = set()
            for entry in entries:
                name = entry.filename.rstrip("/")
                if (
                    not name or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                    or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.flag_bits & 1
                    or name.casefold() in seen
                ):
                    raise ApiProblem(400, "invalid_zip_entry", "The ZIP contains an invalid or duplicate entry.")
                seen.add(name.casefold())
            if not any(not entry.is_dir() for entry in entries):
                raise ApiProblem(400, "empty_project", "The ZIP must contain project files.")
            if archive.testzip() is not None:
                raise BadZipFile("CRC mismatch")
    except (BadZipFile, NotImplementedError, RuntimeError, ZipDecodeError, OSError, EOFError) as error:
        raise ApiProblem(400, "invalid_zip", "Upload a readable, unencrypted ZIP archive.") from error


def read_project_text(
    data: bytes, include: Callable[[PurePosixPath], bool], scope: PurePosixPath | None = None,
) -> Iterator[tuple[PurePosixPath, str]]:
    with ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if not entry.is_dir() and entry.file_size <= MAX_TEXT_FILE and in_scope(path, scope) and include(path):
                yield path, archive.read(entry).decode("utf-8-sig", errors="replace")


def in_scope(path: PurePosixPath, scope: PurePosixPath | None) -> bool:
    return scope is None or path.is_relative_to(scope)


def project_root(paths: list[PurePosixPath], finding_paths: list[PurePosixPath]) -> PurePosixPath:
    gradle_roots = {path.parent for path in paths if path.name in GRADLE_FILES}
    source_roots = {
        PurePosixPath(*path.parts[:path.parts.index("src")])
        for path in finding_paths if "src" in path.parent.parts
    }
    roots = gradle_roots or source_roots
    if not roots:
        return PurePosixPath()
    return PurePosixPath(commonpath([*map(str, roots), *(str(path.parent) for path in finding_paths)]))


def validate_scope(value: object) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 500 or value != value.strip():
        raise ApiProblem(422, "invalid_scan_source", "Specify a relative file or folder inside the project ZIP.")
    if value == ".":
        return
    if any(part in {"", ".", ".."} for part in value.rstrip("/").split("/")) or any(
        character in value for character in ("\\", ":", "\0", "\n", "\r")
    ):
        raise ApiProblem(422, "invalid_scan_source", "Use a relative path without traversal or backslashes.")


def archive_scope(data: bytes, value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path == PurePosixPath():
        return path
    with ZipFile(io.BytesIO(data)) as archive:
        paths = [PurePosixPath(entry.filename) for entry in archive.infolist()]
        files = [PurePosixPath(entry.filename) for entry in archive.infolist() if not entry.is_dir()]
    roots = [PurePosixPath(), project_root(files, [])]
    top_level = {p.parts[0] for p in files if len(p.parts) > 1}
    if len(top_level) == 1 and all(len(p.parts) > 1 for p in files):
        roots.append(PurePosixPath(next(iter(top_level))))
    for root in roots:
        candidate = root / path
        if any(in_scope(entry, candidate) for entry in paths):
            return candidate
    raise ApiProblem(422, "scan_source_not_found", "The selected file or folder is absent from the project ZIP.")


def find_secrets(data: bytes, scope: PurePosixPath | None = None, plugins: Sequence[str] = ()) -> list[Finding]:
    plugin_suffixes = active_suffixes(plugins)
    findings = []
    for path, content in read_project_text(
        data, lambda path: path.suffix.lower() in TEXT_SUFFIXES | plugin_suffixes or path.name.startswith(".env"), scope
    ):
        suffix = path.suffix.lower()
        lines = content.splitlines()
        matched_lines = {
            number: kind for number, line in enumerate(lines, start=1)
            if (kind := secret_assignment_class(line, suffix, is_plugin_code=suffix in plugin_suffixes))
        }
        if suffix in {".kt", ".kts"}:
            matched_lines.update(kotlin_secret_lines(lines))
        for line_number in sorted(matched_lines):
            findings.append(Finding(
                id=uuid4().hex,
                scanner="secrets",
                ruleId="hardcoded-secret",
                secretClass=matched_lines[line_number],
                file=path.as_posix(),
                line=line_number,
                severity="high",
                message="Possible hardcoded credential. Move it to a secret store or environment variable.",
            ))
    return findings


def secret_assignment_class(line: str, suffix: str, *, is_plugin_code: bool = False) -> str | None:
    is_code = is_plugin_code or suffix in CODE_SUFFIXES
    if is_plugin_code:
        line = PYTHON_ANNOTATION.sub(r"\1 =", line) if suffix == ".py" else JS_DECLARATION.sub("", line)
    if not is_code:
        authorization = AUTHORIZATION_VALUE.match(line)
        if authorization and "$" not in authorization[1]:
            return "configuration-token"

    match = SECRET_ASSIGNMENT.match(line)
    if not match:
        return None
    raw_value = match["value"]
    value = raw_value.rstrip(";").strip("\"'")
    quoted = raw_value.startswith(("\"", "'"))
    if not value or value.startswith("$") or (not quoted and (is_code or "(" in value)):
        return None
    key = re.sub(r"[-_.]", "", match["key"].lower())
    if key.endswith(("password", "passwd")):
        return "password"
    if key.endswith("apikey"):
        return "api-key"
    if not is_code and key.endswith("token"):
        return "configuration-token"
    return "hardcoded-secret"


def kotlin_secret_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    local_strings: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith(("//", "*", "/*")):
            local_strings.clear()
            continue
        if KOTLIN_ENV_FALLBACK.search(line):
            yield number, "secret-fallback"

        declaration = KOTLIN_LOCAL.match(line)
        if declaration:
            name, value = declaration.groups()
            local_strings.pop(name, None)
            if re.fullmatch(KOTLIN_STRING, value):
                local_strings[name] = number
            elif number < len(lines) and KOTLIN_CONCAT.fullmatch(value):
                parts = [part.strip() for part in value.split("+")]
                bearer = KOTLIN_BEARER.search(lines[number])
                if bearer and bearer[1] == name and all(part in local_strings for part in parts):
                    yield min(local_strings[part] for part in parts), "recoverable-token"
            continue
        if line.strip():
            local_strings.clear()
