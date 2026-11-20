import io
import os
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Annotated, NamedTuple
from uuid import uuid4
from zipfile import ZipFile

from pydantic import BaseModel, BeforeValidator, Field, StrictBool, StringConstraints, ValidationError

from .kotlin_text import without_comments
from .schemas import Finding, Severity
from .sources import read_project_text


MAX_CATALOG_BYTES = 4 * 1024 * 1024
VERSION = r"[0-9]{1,12}(?:\.[0-9]{1,12}){0,11}"
COORDINATE = r"[A-Za-z0-9_.-]+"
DEPENDENCY_CALL = re.compile(
    rf'\b(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testCompileOnly|'
    rf'testRuntimeOnly|annotationProcessor|kapt|ksp)\s*\(\s*"'
    rf'|\badd\s*\(\s*"[\w]+"\s*,\s*"'
)
GRADLE_NOTATION = re.compile(rf'({COORDINATE}):({COORDINATE})(?::([^":\s]+))?"')
LOCK_ENTRY = re.compile(rf"({COORDINATE}):({COORDINATE}):([^=\s]+)=[\w,]+")
PROPERTY = re.compile(r"^\s*([\w.-]+)\s*[:=]\s*([^\s#!]+)\s*$")
DECLARATION = re.compile(
    r'\b(?:val|var)\s+(\w+)\s*(?::\s*String\s*)?=\s*(?:"([^"\r\n]+)"'
    r'|(?:providers\.gradleProperty|(?:project\.)?property)\(\s*"([^"\r\n]+)"\s*\))'
)
DELEGATED_PROPERTY = re.compile(r"\bval\s+(\w+)(?:\s*:\s*String)?\s+by\s+project\b")
VARIABLE = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")

VersionText = Annotated[str, StringConstraints(pattern=f"^{VERSION}$")]
Coordinate = Annotated[str, StringConstraints(pattern=rf"^{COORDINATE}$", max_length=256)]
AdvisoryID = Annotated[str, StringConstraints(pattern=r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")]


class CatalogUnavailable(ValueError):
    pass


class VersionRange(BaseModel):
    lower: VersionText | None
    lowerInclusive: StrictBool
    upper: VersionText
    upperInclusive: StrictBool

    def contains(self, version: tuple[int, ...]) -> bool:
        if self.lower is not None:
            lower = version_key(self.lower)
            if version < lower or (version == lower and not self.lowerInclusive):
                return False
        upper = version_key(self.upper)
        return version < upper or (version == upper and self.upperInclusive)


class Advisory(BaseModel):
    id: AdvisoryID
    aliases: list[str]
    group: Coordinate
    artifact: Coordinate
    severity: Annotated[Severity, BeforeValidator(lambda value: value.lower() if isinstance(value, str) else value)]
    ranges: list[VersionRange] = Field(min_length=1)
    fixedVersions: list[VersionText]


class Catalog(BaseModel):
    formatVersion: Annotated[int, Field(ge=1, le=1, strict=True)]
    ecosystem: Annotated[str, StringConstraints(pattern=r"^Maven$")]
    versionFormat: Annotated[str, StringConstraints(pattern=r"^numeric-dot-separated$")]
    vulnerabilities: list[Advisory] = Field(min_length=1)


class Dependency(NamedTuple):
    group: str
    artifact: str
    version: str
    path: PurePosixPath
    line: int


def version_key(version: str) -> tuple[int, ...]:
    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def load_catalog(data: bytes) -> Catalog:
    filename = os.getenv("CYBER_GARDEN_ADVISORIES")
    try:
        if filename:
            with Path(filename).open("rb") as source:
                raw = source.read(MAX_CATALOG_BYTES + 1)
        else:
            with ZipFile(io.BytesIO(data)) as archive:
                entries = [
                    entry for entry in archive.infolist()
                    if not entry.is_dir()
                    and PurePosixPath(entry.filename).parts[-2:] == ("vulnerability-database", "vulnerabilities.json")
                ]
                if len(entries) != 1:
                    raise CatalogUnavailable(
                        "SCA needs one vulnerability-database/vulnerabilities.json in the ZIP "
                        "or a server catalog configured through CYBER_GARDEN_ADVISORIES."
                    )
                if entries[0].file_size > MAX_CATALOG_BYTES:
                    raise CatalogUnavailable("The SCA catalog exceeds 4 MiB.")
                raw = archive.read(entries[0])
        if len(raw) > MAX_CATALOG_BYTES:
            raise CatalogUnavailable("The SCA catalog exceeds 4 MiB.")
        return Catalog.model_validate_json(raw)
    except (OSError, ValidationError) as error:
        raise CatalogUnavailable("The SCA catalog could not be read in the expected Maven JSON format.") from error


def gradle_dependencies(data: bytes) -> list[Dependency]:
    filenames = {"build.gradle.kts", "gradle.properties", "gradle.lockfile"}
    files = dict(read_project_text(data, lambda path: path.name in filenames))
    dependencies = []
    declared = set()
    locks: dict[PurePosixPath, dict[tuple[str, str], list[Dependency]]] = {}
    for path, text in files.items():
        if path.name != "gradle.lockfile":
            continue
        locked = defaultdict(list)
        for line, value in enumerate(text.splitlines(), start=1):
            if match := LOCK_ENTRY.fullmatch(value.strip()):
                group, artifact, version = match.groups()
                locked[group, artifact].append(Dependency(group, artifact, version, path, line))
        locks[path.parent] = locked

    for path, text in files.items():
        if path.name != "build.gradle.kts":
            continue
        text = without_comments(text)
        properties = {}
        for parent in reversed(path.parents):
            properties.update(
                match.groups() for line in files.get(parent / "gradle.properties", "").splitlines()
                if (match := PROPERTY.fullmatch(line))
            )
        variables = {name: value or properties.get(prop, "") for name, value, prop in DECLARATION.findall(text)}
        variables.update((name, properties.get(name, "")) for name in DELEGATED_PROPERTY.findall(text))
        for call in DEPENDENCY_CALL.finditer(text):
            notation = GRADLE_NOTATION.match(text, call.end())
            if notation is None:
                continue
            group, artifact, version = notation.groups()
            locked = locks.get(path.parent, {}).get((group, artifact), [])
            versions = {dependency.version for dependency in locked}
            if not versions and version:
                resolved = VARIABLE.sub(lambda match: variables.get(match[1] or match[2], ""), version)
                versions.add(resolved)
            line = text.count("\n", 0, notation.start()) + 1
            for resolved in sorted(versions):
                key = path, group, artifact, resolved
                if key not in declared and re.fullmatch(VERSION, resolved):
                    dependencies.append(Dependency(group, artifact, resolved, path, line))
                    declared.add(key)

    for modules in locks.values():
        for records in modules.values():
            for dep in records:
                key = dep.path.with_name("build.gradle.kts"), dep.group, dep.artifact, dep.version
                if key not in declared and re.fullmatch(VERSION, dep.version):
                    dependencies.append(dep)
                    declared.add(key)
    return dependencies


def find_vulnerable_dependencies(data: bytes) -> list[Finding]:
    catalog = load_catalog(data)
    advisories = defaultdict(list)
    for advisory in catalog.vulnerabilities:
        advisories[advisory.group, advisory.artifact].append(advisory)

    findings = []
    seen = set()
    for dep in gradle_dependencies(data):
        version = version_key(dep.version)
        for advisory in advisories[dep.group, dep.artifact]:
            key = dep.path, dep.group, dep.artifact, dep.version, advisory.id
            if key in seen or not any(interval.contains(version) for interval in advisory.ranges):
                continue
            seen.add(key)
            cve = next((alias for alias in advisory.aliases if CVE.fullmatch(alias)), None)
            fixes = [
                value for value in advisory.fixedVersions
                if version_key(value) > version
                and not any(interval.contains(version_key(value)) for interval in advisory.ranges)
            ]
            advice = (
                f"Upgrade to {min(fixes, key=version_key)} or a supported fixed release."
                if fixes else "Review the advisory and choose a supported fixed release."
            )
            findings.append(Finding(
                id=uuid4().hex, scanner="sca", ruleId="vulnerable-dependency", file=dep.path.as_posix(),
                line=dep.line, severity=advisory.severity,
                message=f"{dep.group}:{dep.artifact}:{dep.version} matches {advisory.id}. {advice}",
                advisoryId=advisory.id, group=dep.group, artifact=dep.artifact, version=dep.version,
                **({"cve": cve} if cve else {}),
            ))
    return findings
