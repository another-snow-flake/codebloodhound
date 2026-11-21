import asyncio
from contextlib import asynccontextmanager, suppress
from typing import Annotated
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, File, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from .ai import answer_report_question
from .exports import export_findings
from .llm import LlmError, ModelSpec, check_model, client_for, default_model_id, list_model_options, resolve_model
from .repositories import download_repository
from .runner import execute_plan, plan_run, validate_edges, validate_node_config
from .schedule import daily_schedule
from .scheduler import poll_schedules
from .schemas import (
    ApiProblem, LlmCheckRequest, LlmCheckResult, LlmOptionOut, LlmSettings, ModelChoice, Node,
    NodeTemplate, NodeTemplateDraft, Position, RepositorySourceRequest,
    RunChatRequest, RunChatResponse, RunCreated,
    RunListItem, RunReport, RunRequest, SourceCreated, Workflow, WorkflowDraft,
)
from .sources import MAX_UPLOAD, validate_zip
from .storage import Storage, database_url
from .webhooks import WebhookError, configured_webhooks


LLM_ERROR_STATUS = {
    "consent_required": 403, "unknown_model": 422, "no_api_key": 409,
    "not_configured": 503, "bad_config": 503, "connection_error": 503, "model_missing": 503,
    "auth_error": 502, "billing_error": 502, "rate_limited": 429, "timeout": 504,
}


def llm_problem(error: LlmError) -> ApiProblem:
    return ApiProblem(LLM_ERROR_STATUS.get(error.code, 502), error.code, str(error))


def fixed_model(choice: ModelChoice) -> ModelSpec:
    """Resolve and pin the model for one request; consent for external providers is checked here."""
    try:
        return resolve_model(choice.modelId, choice.allowExternal)
    except LlmError as error:
        raise llm_problem(error) from None


MAX_NODE_TEMPLATES = 200

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
        scheduler = asyncio.create_task(poll_schedules(storage))
        try:
            yield
        finally:
            scheduler.cancel()
            with suppress(asyncio.CancelledError):
                await scheduler

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
        return save_source(archive)

    def save_source(archive: bytes) -> SourceCreated:
        source_id = uuid4().hex
        storage.save_source(source_id, archive)
        return SourceCreated(sourceId=source_id)

    @app.post("/sources/repository", status_code=201)
    def import_repository(source: RepositorySourceRequest) -> SourceCreated:
        return save_source(download_repository(source.url))

    @app.get("/node-templates")
    def list_node_templates() -> list[NodeTemplate]:
        """Saved nodes shared by the team: custom nodes and standard nodes with their text."""
        return storage.list_node_templates()

    @app.post("/node-templates", status_code=201)
    def create_node_template(draft: NodeTemplateDraft) -> NodeTemplate:
        if draft.type == "trigger":
            raise ApiProblem(422, "invalid_node_template", "A workflow has one trigger; it cannot be saved as a template.")
        validate_node_config(Node(id="template", type=draft.type, position=Position(x=0, y=0), config=draft.config))
        if storage.count_node_templates() >= MAX_NODE_TEMPLATES:
            raise ApiProblem(409, "too_many_node_templates", f"The library holds up to {MAX_NODE_TEMPLATES} saved nodes.")
        template = NodeTemplate(id=uuid4().hex, **draft.model_dump())
        storage.save_node_template(template)
        return template

    @app.post("/node-templates/{template_id}/remove", status_code=204)
    def remove_node_template(template_id: str):
        # POST instead of DELETE: the demo proxy and CORS allow only GET, POST and PUT
        if not storage.delete_node_template(template_id):
            raise ApiProblem(404, "node_template_not_found", "Saved node not found.")

    @app.get("/workflows", response_model_exclude_none=True)
    def list_workflows() -> list[Workflow]:
        return storage.list_workflows()

    def validate_saved_workflow(draft: WorkflowDraft):
        schedule = daily_schedule(draft)
        if schedule is None:
            validate_edges(draft)
            return
        plan_run(draft)
        if storage.get_source(schedule.source_id) is None:
            raise ApiProblem(404, "source_not_found", "The project selected for the schedule was not found.")

    @app.post("/workflows", status_code=201, response_model_exclude_none=True)
    def create_workflow(draft: WorkflowDraft) -> Workflow:
        validate_saved_workflow(draft)
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
        validate_saved_workflow(draft)
        workflow = Workflow(id=workflow_id, **draft.model_dump())
        storage.save_workflow(workflow)
        return workflow

    @app.post("/workflows/{workflow_id}/runs", status_code=202)
    def start_run(workflow_id: str, request: RunRequest, tasks: BackgroundTasks) -> RunCreated:
        workflow = get_workflow(workflow_id)
        plan = plan_run(workflow)
        model = None
        if any(node.type == "ai" for node in plan.nodes):
            try:
                model = resolve_model(request.modelId, request.allowExternal)
            except LlmError as error:
                if request.modelId or error.code not in ("not_configured", "bad_config"):
                    raise llm_problem(error) from None
                # no model configured on the server: scanners still run, the AI node reports the reason
        archive = storage.get_source(request.sourceId)
        if archive is None:
            raise ApiProblem(404, "source_not_found", "Project source not found.")
        report = RunReport.for_workflow(workflow)
        storage.save_run(report)
        tasks.add_task(execute_plan, storage, report, plan, request.sourceId, archive, model)
        return RunCreated(runId=report.runId, status="queued")

    @app.get("/workflows/{workflow_id}/runs")
    def list_runs(
        workflow_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[RunListItem]:
        get_workflow(workflow_id)
        return storage.list_runs(workflow_id, limit, offset)

    @app.get("/runs/{run_id}", response_model_exclude_unset=True)
    def get_run(run_id: str) -> RunReport:
        report = storage.get_run(run_id)
        if report is None:
            raise ApiProblem(404, "run_not_found", "Run not found.")
        return report

    @app.get("/runs/{run_id}/findings.json")
    def download_findings(run_id: str) -> JSONResponse:
        report = get_run(run_id)
        if report.status not in ("succeeded", "failed"):
            raise ApiProblem(409, "run_in_progress", "Wait for the workflow to finish before exporting findings.")
        source_id = next(
            (result.output["sourceId"] for result in report.nodes
             if result.output and isinstance(result.output.get("sourceId"), str)),
            None,
        )
        archive = storage.get_source(source_id) if source_id and report.findings else None
        return JSONResponse(
            export_findings(report.findings, archive),
            headers={"Content-Disposition": 'attachment; filename="findings.json"'},
        )

    @app.post("/runs/{run_id}/chat")
    def chat_about_run(run_id: str, request: RunChatRequest) -> RunChatResponse:
        report = get_run(run_id)
        if report.status not in ("succeeded", "failed"):
            raise ApiProblem(409, "run_in_progress", "Wait for the workflow to finish before asking a question.")
        model = fixed_model(request)  # pinned for this answer, whatever other tabs choose meanwhile
        try:
            reply = answer_report_question(report.findings, request.question, request.history, client_for(model))
        except LlmError as error:
            raise llm_problem(error) from None
        return RunChatResponse(answer=reply, model=model.id)

    @app.get("/settings/llm")
    def get_llm_settings() -> LlmSettings:
        """Models the server offers and the server's default. Each request names its own model."""
        try:
            options = list_model_options()
            default = default_model_id()
        except LlmError as error:
            raise llm_problem(error) from None
        return LlmSettings(defaultId=default, options=[LlmOptionOut(**vars(option)) for option in options])

    @app.post("/settings/llm/check")
    def check_llm(request: LlmCheckRequest) -> LlmCheckResult:
        """Send a synthetic request (no project data) to tell a rejected key, an unreachable
        server and a missing model apart before the editor switches to this model."""
        model = fixed_model(request)
        try:
            seconds = check_model(model)
        except LlmError as error:
            return LlmCheckResult(modelId=model.id, ok=False, code=error.code, message=str(error))
        return LlmCheckResult(modelId=model.id, ok=True, seconds=round(seconds, 2))

    return app


app = create_app()
