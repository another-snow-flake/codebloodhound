import io
import re
import stat
from collections.abc import Callable, Iterator
from pathlib import PurePosixPath
from uuid import uuid4
from zipfile import BadZipFile, ZipFile
from zlib import error as ZipDecodeError

from .schemas import ApiProblem, Finding


MAX_UPLOAD = 10 * 1024 * 1024
MAX_PROJECT_SIZE = 40 * 1024 * 1024
MAX_FILES = 2000
MAX_TEXT_FILE = 1024 * 1024
TEXT_SUFFIXES = {".kt", ".kts", ".java", ".properties", ".yml", ".yaml", ".json", ".toml", ".env"}
CODE_SUFFIXES = {".kt", ".kts", ".java"}
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
    data: bytes, include: Callable[[PurePosixPath], bool]
) -> Iterator[tuple[PurePosixPath, str]]:
    with ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if not entry.is_dir() and entry.file_size <= MAX_TEXT_FILE and include(path):
                yield path, archive.read(entry).decode("utf-8-sig", errors="replace")


def find_secrets(data: bytes) -> list[Finding]:
    findings = []
    for path, content in read_project_text(
        data, lambda path: path.suffix.lower() in TEXT_SUFFIXES or path.name.startswith(".env")
    ):
        suffix = path.suffix.lower()
        lines = content.splitlines()
        matched_lines = {
            number: kind for number, line in enumerate(lines, start=1)
            if (kind := secret_assignment_class(line, suffix))
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


def secret_assignment_class(line: str, suffix: str) -> str | None:
    if suffix not in CODE_SUFFIXES:
        authorization = AUTHORIZATION_VALUE.match(line)
        if authorization and "$" not in authorization[1]:
            return "configuration-token"

    match = SECRET_ASSIGNMENT.match(line)
    if not match:
        return None
    raw_value = match["value"]
    value = raw_value.rstrip(";").strip("\"'")
    quoted = raw_value.startswith(("\"", "'"))
    if not value or value.startswith("$") or (not quoted and (suffix in CODE_SUFFIXES or "(" in value)):
        return None
    key = re.sub(r"[-_.]", "", match["key"].lower())
    if key.endswith(("password", "passwd")):
        return "password"
    if key.endswith("apikey"):
        return "api-key"
    if suffix not in CODE_SUFFIXES and key.endswith("token"):
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
