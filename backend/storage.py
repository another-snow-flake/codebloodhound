import os

import psycopg
from psycopg.types.json import Jsonb

from .schemas import NodeTemplate, RunListItem, RunReport, Workflow


DEFAULT_DATABASE_URL = "postgresql://cyber_garden:cyber_garden_dev@127.0.0.1:5432/cyber_garden"


def database_url() -> str:
    return os.environ.get("DATABASE_URL") or DEFAULT_DATABASE_URL


class Storage:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def connect(self):
        return psycopg.connect(self.dsn, connect_timeout=5)

    def initialize(self, *, recover_interrupted: bool = True):
        with self.connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, archive BYTEA NOT NULL)")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS workflows (
                    id TEXT PRIMARY KEY,
                    body JSONB NOT NULL,
                    created_order BIGINT GENERATED ALWAYS AS IDENTITY
                )
            """)
            connection.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, body JSONB NOT NULL)")
            connection.execute("""
                CREATE INDEX IF NOT EXISTS runs_workflow_history_idx
                ON runs ((body ->> 'workflowId'), (body ->> 'createdAt') DESC NULLS LAST, id DESC)
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS node_templates (
                    id TEXT PRIMARY KEY,
                    body JSONB NOT NULL,
                    created_order BIGINT GENERATED ALWAYS AS IDENTITY
                )
            """)
            if not recover_interrupted:
                return
            interrupted = connection.execute("""
                SELECT body FROM runs WHERE body ->> 'status' IN ('queued', 'running') FOR UPDATE
            """).fetchall()
            for (body,) in interrupted:
                report = RunReport.model_validate(body)
                report.status = "failed"
                for node in report.nodes:
                    if node.status in ("queued", "running"):
                        node.status = "failed" if node.status == "running" else "skipped"
                        node.error = "Execution was interrupted by a backend restart."
                connection.execute(
                    "UPDATE runs SET body = %s WHERE id = %s",
                    (Jsonb(report.model_dump(mode="json", exclude_unset=True)), report.runId),
                )

    def save_source(self, source_id: str, archive: bytes):
        with self.connect() as connection:
            connection.execute("INSERT INTO sources (id, archive) VALUES (%s, %s)", (source_id, archive))

    def get_source(self, source_id: str) -> bytes | None:
        with self.connect() as connection:
            row = connection.execute("SELECT archive FROM sources WHERE id = %s", (source_id,)).fetchone()
        return row[0] if row else None

    def list_workflows(self) -> list[Workflow]:
        with self.connect() as connection:
            rows = connection.execute("SELECT body FROM workflows ORDER BY created_order DESC").fetchall()
        return [Workflow.model_validate(body) for (body,) in rows]

    def get_workflow(self, workflow_id: str) -> Workflow | None:
        with self.connect() as connection:
            row = connection.execute("SELECT body FROM workflows WHERE id = %s", (workflow_id,)).fetchone()
        return Workflow.model_validate(row[0]) if row else None

    def save_workflow(self, workflow: Workflow):
        with self.connect() as connection:
            connection.execute("""
                INSERT INTO workflows (id, body) VALUES (%s, %s)
                ON CONFLICT(id) DO UPDATE SET body = excluded.body
            """, (workflow.id, Jsonb(workflow.model_dump(mode="json"))))

    def list_node_templates(self) -> list[NodeTemplate]:
        with self.connect() as connection:
            rows = connection.execute("SELECT body FROM node_templates ORDER BY created_order DESC").fetchall()
        return [NodeTemplate.model_validate(body) for (body,) in rows]

    def count_node_templates(self) -> int:
        with self.connect() as connection:
            return connection.execute("SELECT count(*) FROM node_templates").fetchone()[0]

    def save_node_template(self, template: NodeTemplate):
        with self.connect() as connection:
            connection.execute("INSERT INTO node_templates (id, body) VALUES (%s, %s)",
                               (template.id, Jsonb(template.model_dump(mode="json"))))

    def delete_node_template(self, template_id: str) -> bool:
        with self.connect() as connection:
            return connection.execute("DELETE FROM node_templates WHERE id = %s", (template_id,)).rowcount > 0

    def save_run(self, report: RunReport):
        with self.connect() as connection:
            connection.execute("""
                INSERT INTO runs (id, body) VALUES (%s, %s)
                ON CONFLICT(id) DO UPDATE SET body = excluded.body
            """, (report.runId, Jsonb(report.model_dump(mode="json", exclude_unset=True))))

    def get_run(self, run_id: str) -> RunReport | None:
        with self.connect() as connection:
            row = connection.execute("SELECT body FROM runs WHERE id = %s", (run_id,)).fetchone()
        return RunReport.model_validate(row[0]) if row else None

    def list_runs(self, workflow_id: str, limit: int, offset: int) -> list[RunListItem]:
        with self.connect() as connection:
            rows = connection.execute("""
                SELECT id, body ->> 'status', body ->> 'createdAt',
                       jsonb_array_length(COALESCE(body -> 'findings', '[]'::jsonb))
                FROM runs
                WHERE body ->> 'workflowId' = %s
                ORDER BY body ->> 'createdAt' DESC NULLS LAST, id DESC
                LIMIT %s OFFSET %s
            """, (workflow_id, limit, offset)).fetchall()
        return [
            RunListItem(runId=run_id, status=status, createdAt=created_at, findingCount=count)
            for run_id, status, created_at, count in rows
        ]
