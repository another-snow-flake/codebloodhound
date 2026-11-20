# CodeBloodhound

Visual drag-and-drop platform for automating code security checks: build workflows from nodes, run custom secret/SCA/SAST scanners, get AI-powered explanations and fixes, and send reports to developers.

Built for **Cyber Garden 2026**. Workflows target organizer-provided or team-owned training projects using Kotlin, Spring Boot, and Gradle Kotlin DSL.

## Current prototype

The FastAPI backend accepts a ZIP of a training project, saves workflow graphs in PostgreSQL 17, and runs them on demand. The first workflow finds possible hardcoded secrets, branches on severity, and returns per-node status and a report with file names and line numbers. Reports omit the credential values.

The visual editor, dependency and static analysis, scheduled runs, AI recommendations, and notifications are planned for the full MVP.

## Quick start

From the repository root in PowerShell, with Python 3.12 and Docker Compose available:

```powershell
docker compose up -d --wait db
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Open [Swagger UI](http://127.0.0.1:8000/docs). Follow the example in the [backend guide](BACKEND.md) to upload a ZIP, save a `trigger → secrets → condition` graph, and retrieve its report. [OpenAPI JSON](http://127.0.0.1:8000/openapi.json) describes the available endpoints.

## Project files

| Path | Contents |
| --- | --- |
| [`backend/`](backend/) | FastAPI routes, workflow execution, secret detection, and PostgreSQL storage |
| [`compose.yaml`](compose.yaml) | Local PostgreSQL service and persistent volume |
| [`BACKEND.md`](BACKEND.md) | API walkthrough, example workflow, and SQLite import |
| [`AGENTS.md`](AGENTS.md) | Team responsibilities, data contracts, and development rules |
