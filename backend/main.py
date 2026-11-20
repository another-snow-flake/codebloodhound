from contextlib import asynccontextmanager
from typing import Annotated
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, File, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from .ai import answer_report_question
from .llm import LlmError, list_model_options, load_llm, select_model, selected_model_id
from .runner import execute_plan, plan_run, validate_edges
from .schemas import (
    ApiProblem, LlmOptionOut, LlmSelection, LlmSettings, NodeResult, RunChatRequest, RunChatResponse, RunCreated,
    RunReport, RunRequest, SourceCreated, Workflow, WorkflowDraft,
)
from .sources import MAX_UPLOAD, validate_zip
from .storage import Storage, database_url
from .webhooks import WebhookError, configured_webhooks


LOCAL_ORIGINS = [
    f"http://{host}:{port}"
    for host in ("localhost", "127.0.0.1")
    for port in (3000, 5173)
]


def create_app(dsn: str | None = None) -> FastAPI:
    storage = Storage(dsn if dsn is not None else database_url())

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        storage.initialize()
        yield

    app = FastAPI(title="Cyber Garden Workflow API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware, allow_origins=LOCAL_ORIGINS, allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type"]
    )

    @app.exception_handler(ApiProblem)
    async def api_error(_: Request, problem: ApiProblem):
        return JSONResponse(status_code=problem.status, content={"code": problem.code, "message": str(problem)})

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_: Request, error: RequestValidationError):
        location = ".".join(str(part) for part in error.errors()[0]["loc"])
        return JSONResponse(status_code=422, content={"code": "invalid_request", "message": f"Invalid field: {location}."})

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, error: HTTPException):
        return JSONResponse(
            status_code=error.status_code,
            content={"code": "http_error", "message": str(error.detail)},
            headers=error.headers,
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/webhooks")
    def list_webhooks() -> list[str]:
        try:
            return sorted(configured_webhooks())
        except WebhookError as error:
            raise ApiProblem(503, error.code, str(error)) from None

    @app.post("/sources", status_code=201)
    def upload_source(file: Annotated[UploadFile, File(description="ZIP archive of an approved training project")]) -> SourceCreated:
        archive = file.file.read(MAX_UPLOAD + 1)
        if len(archive) > MAX_UPLOAD:
            raise ApiProblem(413, "upload_too_large", "Upload a ZIP up to 10 MiB.")
        validate_zip(archive)
        source_id = uuid4().hex
        storage.save_source(source_id, archive)
        return SourceCreated(sourceId=source_id)

    @app.get("/workflows", response_model_exclude_none=True)
    def list_workflows() -> list[Workflow]:
        return storage.list_workflows()

    @app.post("/workflows", status_code=201, response_model_exclude_none=True)
    def create_workflow(draft: WorkflowDraft) -> Workflow:
        validate_edges(draft)
        workflow = Workflow(id=uuid4().hex, **draft.model_dump())
        storage.save_workflow(workflow)
        return workflow

    @app.get("/workflows/{workflow_id}", response_model_exclude_none=True)
    def get_workflow(workflow_id: str) -> Workflow:
        workflow = storage.get_workflow(workflow_id)
        if workflow is None:
            raise ApiProblem(404, "workflow_not_found", "Workflow not found.")
        return workflow

    @app.put("/workflows/{workflow_id}", response_model_exclude_none=True)
    def update_workflow(workflow_id: str, draft: WorkflowDraft) -> Workflow:
        get_workflow(workflow_id)
        validate_edges(draft)
        workflow = Workflow(id=workflow_id, **draft.model_dump())
        storage.save_workflow(workflow)
        return workflow

    @app.post("/workflows/{workflow_id}/runs", status_code=202)
    def start_run(workflow_id: str, request: RunRequest, tasks: BackgroundTasks) -> RunCreated:
        workflow = get_workflow(workflow_id)
        plan = plan_run(workflow)
        archive = storage.get_source(request.sourceId)
        if archive is None:
            raise ApiProblem(404, "source_not_found", "Project source not found.")
        report = RunReport(
            runId=uuid4().hex,
            workflowId=workflow_id,
            status="queued",
            nodes=[NodeResult(nodeId=node.id, status="queued") for node in workflow.nodes],
            findings=[],
        )
        storage.save_run(report)
        tasks.add_task(execute_plan, storage, report, plan, request.sourceId, archive)
        return RunCreated(runId=report.runId, status="queued")

    @app.get("/runs/{run_id}", response_model_exclude_unset=True)
    def get_run(run_id: str) -> RunReport:
        report = storage.get_run(run_id)
        if report is None:
            raise ApiProblem(404, "run_not_found", "Run not found.")
        return report

    @app.post("/runs/{run_id}/chat")
    def chat_about_run(run_id: str, request: RunChatRequest) -> RunChatResponse:
        report = get_run(run_id)
        if report.status not in ("succeeded", "failed"):
            raise ApiProblem(409, "run_in_progress", "Wait for the workflow to finish before asking a question.")
        try:
            client = load_llm()  # taken once: a model switch during the answer does not affect it
            reply = answer_report_question(report.findings, request.question, request.history, client)
        except LlmError as error:
            status = {
                "not_configured": 503, "bad_config": 503, "connection_error": 503, "model_missing": 503,
                "rate_limited": 429, "timeout": 504,
            }.get(error.code, 502)
            raise ApiProblem(status, error.code, str(error)) from None
        return RunChatResponse(answer=reply, model=f"{client.provider}:{client.model}")

    def llm_settings() -> LlmSettings:
        try:
            options = list_model_options()
            selected = selected_model_id()
        except LlmError as error:
            raise ApiProblem(503, error.code, str(error)) from None
        return LlmSettings(
            selectedId=selected,
            options=[LlmOptionOut(**vars(option)) for option in options],
        )

    @app.get("/settings/llm")
    def get_llm_settings() -> LlmSettings:
        """Models the server offers, their status, and the one used for the next AI request."""
        return llm_settings()

    @app.put("/settings/llm")
    def put_llm_settings(selection: LlmSelection) -> LlmSettings:
        """Switch the model for the next AI node run and chat message without restarting the API."""
        try:
            select_model(selection.modelId, list_model_options())
        except LlmError as error:
            status = {"unknown_model": 404, "no_api_key": 409}.get(error.code, 503)
            raise ApiProblem(status, error.code, str(error)) from None
        return llm_settings()

    return app


app = create_app()
