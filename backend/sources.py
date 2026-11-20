import io
import re
import stat
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
SECRET_ASSIGNMENT = re.compile(
    r'''(?ix)^\s*(?:(?:export|val|var)\s+)?
    ["']?(?P<key>[\w.-]*(?:password|passwd|secret|token|api[-_.]?key))["']?
    \s*(?::\s*String\??\s*=|[:=])\s*(?P<value>[^\s#,]+)'''
)


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


def find_secrets(data: bytes) -> list[Finding]:
    findings = []
    with ZipFile(io.BytesIO(data)) as archive:
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if entry.is_dir() or entry.file_size > MAX_TEXT_FILE:
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and not path.name.startswith(".env"):
                continue
            content = archive.read(entry).decode("utf-8-sig", errors="replace")
            for line_number, line in enumerate(content.splitlines(), start=1):
                match = SECRET_ASSIGNMENT.match(line)
                if not match:
                    continue
                raw_value = match["value"]
                value = raw_value.rstrip(";").strip("\"'")
                if not value or value.startswith("$"):
                    continue
                quoted = raw_value.startswith(("\"", "'"))
                if not quoted and (path.suffix.lower() in {".kt", ".kts", ".java"} or "(" in value):
                    continue
                findings.append(Finding(
                    id=uuid4().hex,
                    scanner="secrets",
                    ruleId="hardcoded-secret",
                    file=path.as_posix(),
                    line=line_number,
                    severity="high",
                    message="Possible hardcoded credential. Move it to a secret store or environment variable.",
                ))
    return findings
