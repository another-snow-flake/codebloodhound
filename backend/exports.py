import io
from pathlib import PurePosixPath
from zipfile import ZipFile

from pydantic import JsonValue

from .language_plugins import LANGUAGE_SUFFIXES, active_suffixes
from .schemas import Finding
from .sources import GRADLE_FILES, find_secrets, is_project_text, project_root


def export_findings(findings: list[Finding], archive: bytes | None) -> dict[str, list[dict[str, JsonValue]]]:
    finding_paths = [PurePosixPath(finding.file) for finding in findings]
    paths = finding_paths
    project_paths = finding_paths
    recovered_classes = {}
    if archive is not None and findings:
        with ZipFile(io.BytesIO(archive)) as project:
            paths = [PurePosixPath(entry.filename) for entry in project.infolist() if not entry.is_dir()]
        suffixes = active_suffixes(tuple(LANGUAGE_SUFFIXES))
        project_paths = [path for path in paths if path.name in GRADLE_FILES or is_project_text(path, suffixes)]
        if any(finding.scanner == "secrets" and not finding.secretClass for finding in findings):
            recovered_classes = {
                (finding.file, finding.line): finding.secretClass for finding in find_secrets(archive)
            }
    root = project_root(paths, project_paths)
    if any(not path.is_relative_to(root) for path in finding_paths):
        root = project_root(paths, [*project_paths, *finding_paths])

    entries = []
    for finding, path in zip(findings, finding_paths):
        entry: dict[str, JsonValue] = {
            "category": "SECRET" if finding.scanner == "secrets" else finding.scanner.upper(),
            "path": path.relative_to(root).as_posix(),
            "severity": finding.severity.upper(),
            "description": finding.message,
        }
        if finding.scanner == "sca":
            entry.update(
                group=finding.group,
                artifact=finding.artifact,
                version=finding.version,
                advisoryId=finding.advisoryId or finding.cve,
            )
        else:
            entry["class"] = finding.secretClass or recovered_classes.get((finding.file, finding.line)) or finding.ruleId
            entry["line"] = finding.line
        entries.append(entry)
    return {"findings": entries}
