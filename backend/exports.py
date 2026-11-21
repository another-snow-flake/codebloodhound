import io
from pathlib import PurePosixPath
from zipfile import ZipFile

from pydantic import JsonValue

from .schemas import Finding
from .sources import find_secrets, project_root


def export_findings(findings: list[Finding], archive: bytes | None) -> dict[str, list[dict[str, JsonValue]]]:
    finding_paths = [PurePosixPath(finding.file) for finding in findings]
    paths = finding_paths
    recovered_classes = {}
    if archive is not None and findings:
        with ZipFile(io.BytesIO(archive)) as project:
            paths = [PurePosixPath(entry.filename) for entry in project.infolist() if not entry.is_dir()]
        if any(finding.scanner == "secrets" and not finding.secretClass for finding in findings):
            recovered_classes = {
                (finding.file, finding.line): finding.secretClass for finding in find_secrets(archive)
            }
    root = project_root(paths, finding_paths)

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
