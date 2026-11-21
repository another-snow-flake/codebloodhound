import os
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import psycopg
from psycopg.types.json import Jsonb

from .accounts import Account
from .schedule import DailySchedule, daily_schedule
from .schemas import ApiProblem, NodeTemplate, RunListItem, RunReport, Workflow, WorkflowDraft
from .user_plugins import MAX_USER_PLUGINS, PluginDraft


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
            connection.execute("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash BYTEA NOT NULL,
                    language_plugins TEXT[] NOT NULL DEFAULT '{}'
                )
            """)
            connection.execute("ALTER TABLE accounts ADD COLUMN IF NOT EXISTS email TEXT")
            connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS accounts_email_unique ON accounts (lower(email))")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS account_sessions (
                    digest BYTEA PRIMARY KEY,
                    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days')
                )
            """)
            connection.execute("CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, archive BYTEA NOT NULL)")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS workflows (
                    id TEXT PRIMARY KEY,
                    body JSONB NOT NULL,
                    created_order BIGINT GENERATED ALWAYS AS IDENTITY
                )
            """)
            connection.execute("ALTER TABLE sources ADD COLUMN IF NOT EXISTS owner_id TEXT REFERENCES accounts(id)")
            connection.execute("ALTER TABLE workflows ADD COLUMN IF NOT EXISTS owner_id TEXT REFERENCES accounts(id)")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS workflow_templates (
                    id TEXT PRIMARY KEY,
                    workflow_id TEXT UNIQUE NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
                    owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    tags TEXT[] NOT NULL,
                    draft JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS user_plugins (
                    id TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    description TEXT NOT NULL,
                    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'public')),
                    config JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """)
            connection.execute("CREATE INDEX IF NOT EXISTS user_plugins_owner_idx ON user_plugins (owner_id)")
            connection.execute("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, body JSONB NOT NULL)")
            connection.execute("""
                CREATE INDEX IF NOT EXISTS runs_workflow_history_idx
                ON runs ((body ->> 'workflowId'), (body ->> 'createdAt') DESC NULLS LAST, id DESC)
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS daily_schedules (
                    workflow_id TEXT PRIMARY KEY REFERENCES workflows(id) ON DELETE CASCADE,
                    source_id TEXT NOT NULL REFERENCES sources(id),
                    wall_time TEXT NOT NULL,
                    time_zone TEXT NOT NULL,
                    next_at TIMESTAMPTZ NOT NULL
                )
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

    def create_account(self, account: Account, digest: bytes) -> bool:
        with self.connect() as connection:
            return bool(connection.execute(
                "INSERT INTO accounts (id, username, email, password_hash) VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (account.id, account.username, account.email, digest),
            ).rowcount)

    def account_login(self, username: str) -> tuple[Account, bytes] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id, username, email, language_plugins, password_hash FROM accounts WHERE username = %s", (username,),
            ).fetchone()
        if row is None:
            return None
        account_id, name, email, plugins, digest = row
        return Account(id=account_id, username=name, email=email, languagePlugins=plugins), digest

    def save_session(self, digest: bytes, account_id: str) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM account_sessions WHERE expires_at <= now()")
            connection.execute("INSERT INTO account_sessions (digest, account_id) VALUES (%s, %s)", (digest, account_id))

    def session_account(self, digest: bytes) -> Account | None:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT a.id, a.username, a.email, a.language_plugins FROM account_sessions s
                JOIN accounts a ON a.id = s.account_id
                WHERE s.digest = %s AND s.expires_at > now()
            """, (digest,)).fetchone()
        return Account(id=row[0], username=row[1], email=row[2], languagePlugins=row[3]) if row else None

    def delete_session(self, digest: bytes) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM account_sessions WHERE digest = %s", (digest,))

    def save_language_plugins(self, account: Account) -> None:
        with self.connect() as connection:
            connection.execute("UPDATE accounts SET language_plugins = %s WHERE id = %s",
                               (account.languagePlugins, account.id))

    def save_source(self, source_id: str, archive: bytes, *, owner_id: str | None = None):
        with self.connect() as connection:
            connection.execute("INSERT INTO sources (id, archive, owner_id) VALUES (%s, %s, %s)", (source_id, archive, owner_id))

    def get_source(self, source_id: str, *, owner_id: str | None = None) -> bytes | None:
        with self.connect() as connection:
            row = connection.execute("SELECT archive FROM sources WHERE id = %s AND (owner_id IS NULL OR owner_id = %s)",
                                     (source_id, owner_id)).fetchone()
        return row[0] if row else None

    def list_workflows(self, *, owner_id: str | None = None) -> list[Workflow]:
        with self.connect() as connection:
            rows = connection.execute("""
                SELECT w.body, a.language_plugins FROM workflows w LEFT JOIN accounts a ON a.id = w.owner_id
                WHERE w.owner_id IS NULL OR w.owner_id = %s ORDER BY w.created_order DESC
            """, (owner_id,)).fetchall()
        return [Workflow.model_validate({**body, "languagePlugins": plugins}) for body, plugins in rows]

    def get_workflow(self, workflow_id: str, *, owner_id: str | None = None) -> Workflow | None:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT w.body, a.language_plugins FROM workflows w LEFT JOIN accounts a ON a.id = w.owner_id
                WHERE w.id = %s AND (w.owner_id IS NULL OR w.owner_id = %s)
            """, (workflow_id, owner_id)).fetchone()
        return Workflow.model_validate({**row[0], "languagePlugins": row[1]}) if row else None

    def save_workflow(self, workflow: Workflow, *, owner_id: str | None = None):
        schedule = daily_schedule(workflow)
        with self.connect() as connection:
            connection.execute("""
                INSERT INTO workflows (id, body, owner_id) VALUES (%s, %s, %s)
                ON CONFLICT(id) DO UPDATE SET body = excluded.body
            """, (workflow.id, Jsonb(workflow.model_dump(mode="json", exclude={"languagePlugins"})), owner_id))
            if schedule is None:
                connection.execute("DELETE FROM daily_schedules WHERE workflow_id = %s", (workflow.id,))
            else:
                connection.execute("""
                    INSERT INTO daily_schedules (workflow_id, source_id, wall_time, time_zone, next_at)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (workflow_id) DO UPDATE SET
                        source_id = excluded.source_id, wall_time = excluded.wall_time,
                        time_zone = excluded.time_zone, next_at = excluded.next_at
                    WHERE (daily_schedules.source_id, daily_schedules.wall_time, daily_schedules.time_zone)
                       IS DISTINCT FROM (excluded.source_id, excluded.wall_time, excluded.time_zone)
                """, (
                    workflow.id, schedule.source_id, schedule.wall_time, schedule.zone.key,
                    schedule.next_after(datetime.now(timezone.utc)),
                ))

    def list_node_templates(self) -> list[NodeTemplate]:
        with self.connect() as connection:
            rows = connection.execute("SELECT body FROM node_templates ORDER BY created_order DESC").fetchall()
        return [NodeTemplate.model_validate(body) for (body,) in rows]

    def list_public_templates(self, viewer_id: str | None, query: str, limit: int, offset: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("""
                SELECT t.id, t.title, t.description, t.tags, a.username, t.updated_at,
                       CASE WHEN t.owner_id = %s THEN t.workflow_id END
                FROM workflow_templates t JOIN accounts a ON a.id = t.owner_id
                WHERE strpos(lower(t.title || ' ' || t.description || ' ' || COALESCE(array_to_string(t.tags, ' '), '')), lower(%s)) > 0
                ORDER BY t.updated_at DESC, t.id DESC
                LIMIT %s OFFSET %s
            """, (viewer_id, query, limit, offset)).fetchall()
        return [self._template_summary(row) for row in rows]

    @staticmethod
    def _template_summary(row) -> dict:
        template_id, title, description, tags, author, updated_at, workflow_id = row
        return dict(id=template_id, title=title, description=description, tags=tags, author=author,
                    updatedAt=updated_at, workflowId=workflow_id)

    def get_public_template(self, template_id: str, viewer_id: str | None) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT t.id, t.title, t.description, t.tags, a.username, t.updated_at,
                       CASE WHEN t.owner_id = %s THEN t.workflow_id END, t.draft
                FROM workflow_templates t JOIN accounts a ON a.id = t.owner_id WHERE t.id = %s
            """, (viewer_id, template_id)).fetchone()
        return {**self._template_summary(row[:-1]), "draft": row[-1]} if row else None

    def publish_workflow_template(
        self, template_id: str, owner: Account, workflow_id: str,
        title: str, description: str, tags: list[str], draft: WorkflowDraft,
    ) -> dict:
        with self.connect() as connection:
            row = connection.execute("""
                INSERT INTO workflow_templates (id, workflow_id, owner_id, title, description, tags, draft)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (workflow_id) DO UPDATE SET
                    title = excluded.title, description = excluded.description, tags = excluded.tags,
                    draft = excluded.draft, updated_at = now()
                RETURNING id, updated_at
            """, (template_id, workflow_id, owner.id, title, description, tags,
                  Jsonb(draft.model_dump(mode="json", exclude_none=True)))).fetchone()
        return dict(id=row[0], title=title, description=description, tags=tags, author=owner.username,
                    updatedAt=row[1], workflowId=workflow_id)

    def remove_public_template(self, template_id: str, owner_id: str) -> bool:
        with self.connect() as connection:
            return bool(connection.execute(
                "DELETE FROM workflow_templates WHERE id = %s AND owner_id = %s", (template_id, owner_id),
            ).rowcount)

    @staticmethod
    def _plugin_record(row) -> dict:
        plugin_id, author, owned, description, visibility, config, updated_at = row
        return dict(id=plugin_id, author=author, owned=owned, description=description, visibility=visibility,
                    config=config, updatedAt=updated_at)

    def list_plugins(self, viewer_id: str | None, query: str, limit: int, offset: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("""
                SELECT p.id, a.username, COALESCE(p.owner_id = %s, false), p.description, p.visibility, p.config, p.updated_at
                FROM user_plugins p JOIN accounts a ON a.id = p.owner_id
                WHERE (p.visibility = 'public' OR p.owner_id = %s)
                  AND strpos(lower(concat_ws(' ', p.config ->> 'title', p.description, a.username,
                      CASE p.config ->> 'language' WHEN 'javascript' THEN 'JavaScript TypeScript'
                           ELSE p.config ->> 'language' END)), lower(%s)) > 0
                ORDER BY p.updated_at DESC, p.id DESC
                LIMIT %s OFFSET %s
            """, (viewer_id, viewer_id, query, limit, offset)).fetchall()
        return [self._plugin_record(row) for row in rows]

    def get_plugin(self, plugin_id: str, viewer_id: str | None) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT p.id, a.username, COALESCE(p.owner_id = %s, false), p.description, p.visibility, p.config, p.updated_at
                FROM user_plugins p JOIN accounts a ON a.id = p.owner_id
                WHERE p.id = %s AND (p.visibility = 'public' OR p.owner_id = %s)
            """, (viewer_id, plugin_id, viewer_id)).fetchone()
        return self._plugin_record(row) if row else None

    def save_plugin(self, plugin_id: str, account: Account, draft: PluginDraft, *, create: bool) -> dict | None:
        with self.connect() as connection:
            if create:
                connection.execute("SELECT id FROM accounts WHERE id = %s FOR UPDATE", (account.id,))
                count, = connection.execute(
                    "SELECT count(*) FROM user_plugins WHERE owner_id = %s", (account.id,),
                ).fetchone()
                if count >= MAX_USER_PLUGINS:
                    raise ApiProblem(409, "plugin_limit_reached", "The account has reached its plugin limit.")
                row = connection.execute("""
                    INSERT INTO user_plugins (id, owner_id, description, visibility, config)
                    VALUES (%s, %s, %s, %s, %s) RETURNING updated_at
                """, (plugin_id, account.id, draft.description, draft.visibility, Jsonb(draft.config))).fetchone()
            else:
                row = connection.execute("""
                    UPDATE user_plugins SET description = %s, visibility = %s, config = %s, updated_at = now()
                    WHERE id = %s AND owner_id = %s RETURNING updated_at
                """, (draft.description, draft.visibility, Jsonb(draft.config), plugin_id, account.id)).fetchone()
        if row is None:
            return None
        return dict(id=plugin_id, author=account.username, owned=True, updatedAt=row[0], **draft.model_dump())

    def remove_plugin(self, plugin_id: str, owner_id: str) -> bool:
        with self.connect() as connection:
            return bool(connection.execute(
                "DELETE FROM user_plugins WHERE id = %s AND owner_id = %s", (plugin_id, owner_id),
            ).rowcount)

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
            self._save_run(connection, report)

    @staticmethod
    def _save_run(connection, report: RunReport):
        connection.execute("""
            INSERT INTO runs (id, body) VALUES (%s, %s)
            ON CONFLICT(id) DO UPDATE SET body = excluded.body
        """, (report.runId, Jsonb(report.model_dump(mode="json", exclude_unset=True))))

    def claim_daily_run(self, now: datetime) -> tuple[Workflow, RunReport, str, bytes] | None:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT schedule.source_id, schedule.wall_time, schedule.time_zone, schedule.next_at,
                       workflows.body, sources.archive, accounts.language_plugins
                FROM daily_schedules AS schedule
                JOIN workflows ON workflows.id = schedule.workflow_id
                JOIN sources ON sources.id = schedule.source_id
                LEFT JOIN accounts ON accounts.id = workflows.owner_id
                WHERE schedule.next_at <= %s AND (sources.owner_id IS NULL OR sources.owner_id = workflows.owner_id)
                ORDER BY schedule.next_at, schedule.workflow_id
                LIMIT 1
                FOR UPDATE OF schedule SKIP LOCKED
            """, (now,)).fetchone()
            if row is None:
                return None
            source_id, wall_time, zone, due_at, body, archive, plugins = row
            workflow = Workflow.model_validate({**body, "languagePlugins": plugins})
            report = RunReport.for_workflow(workflow, due_at)
            next_at = DailySchedule(source_id, wall_time, ZoneInfo(zone)).next_after(now)
            connection.execute("UPDATE daily_schedules SET next_at = %s WHERE workflow_id = %s", (next_at, workflow.id))
            self._save_run(connection, report)
            return workflow, report, source_id, archive

    def get_run(self, run_id: str, *, owner_id: str | None = None) -> RunReport | None:
        with self.connect() as connection:
            row = connection.execute("""
                SELECT r.body FROM runs r LEFT JOIN workflows w ON w.id = r.body ->> 'workflowId'
                WHERE r.id = %s AND (w.owner_id IS NULL OR w.owner_id = %s)
            """, (run_id, owner_id)).fetchone()
        return RunReport.model_validate(row[0]) if row else None

    def list_runs(self, workflow_id: str, limit: int, offset: int) -> list[RunListItem]:
        with self.connect() as connection:
            rows = connection.execute("""
                SELECT id, body ->> 'status', body ->> 'createdAt', COALESCE(body ->> 'triggerMode', 'manual'),
                       jsonb_array_length(COALESCE(body -> 'findings', '[]'::jsonb))
                FROM runs
                WHERE body ->> 'workflowId' = %s
                ORDER BY body ->> 'createdAt' DESC NULLS LAST, id DESC
                LIMIT %s OFFSET %s
            """, (workflow_id, limit, offset)).fetchall()
        return [
            RunListItem(runId=run_id, status=status, createdAt=created_at, triggerMode=trigger_mode, findingCount=count)
            for run_id, status, created_at, trigger_mode, count in rows
        ]
