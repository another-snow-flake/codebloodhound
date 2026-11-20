# CodeBloodhound

Проект для Cyber Garden 2026 · A Cyber Garden 2026 project

[Русский](#русский) · [English](#english)

## Русский

Делаем конструктор проверок безопасности для учебных проектов на Kotlin, Spring Boot и Gradle Kotlin DSL. Сейчас в редакторе можно собрать сценарий из нод, сохранить его, запустить поиск зашитых паролей, токенов и ключей и скачать схему в JSON. В отчёте видны статусы нод, критичность, файл и строка каждой находки.

### Локальный запуск

Установите Python 3.12 и запустите Docker. Из корня проекта выполните [команды запуска](#launch) в PowerShell. Первый терминал поднимает PostgreSQL 17 и FastAPI, второй раздаёт статический фронтенд. Откройте [редактор](http://127.0.0.1:5173) или [Swagger UI](http://127.0.0.1:8000/docs).

По умолчанию редактор обращается к FastAPI на `127.0.0.1:8000`. Адрес можно поменять в настройках. Для локального фронтенда разрешены `localhost` и `127.0.0.1` на портах `5173` и `3000`. PostgreSQL хранит данные в томе `postgres_data`, таблицы создаются при запуске API. Со своей базой можно пропустить команду Docker и задать [`DATABASE_URL`](#database) перед запуском FastAPI.

### Первая проверка

1. Соберите [учебный ZIP](#sample-zip) или возьмите проект организаторов. Загружайте только разрешённые учебные проекты. Лимит ZIP — 10 МиБ, после распаковки — 40 МиБ и 2000 записей.
2. В редакторе выберите ZIP, нажмите «Загрузить», затем «Запустить». Начальный сценарий уже содержит ноды запуска, поиска секретов и условия по критичности.
3. В отчёте для примера появится одна находка `high` в `application.properties:1`, а условие сработает. Значение пароля в отчёт не попадает. Сохранённый сценарий можно открыть в «Мои сценарии», а схему скачать через меню «Файл».

Для работы напрямую с API используйте [запросы и пример графа](#workflow-api). Если остались данные старого SQLite-прототипа, запустите PostgreSQL и выполните [импорт](#database) перед запуском FastAPI. Он сохранит ID архивов, сценариев и отчётов, а при повторном запуске пропустит уже перенесённые записи.

Пока это одно локальное рабочее пространство. Аккаунты, загрузка по ссылке, расписание, SCA, SAST, AI и уведомления ещё в работе. Черновики принимают все типы нод, а попытка запустить неподключённую ноду вернёт `422 unsupported_node`.

При разработке сверяйте изменения API с фронтендом и проверяйте их на синтетических данных. Анализаторы сами ищут проблемы. LLM будет объяснять уже найденное. Ключи и токены хранятся на бэкенде.

## English

We're building a security workflow editor for training projects that use Kotlin, Spring Boot, and Gradle Kotlin DSL. You can build and save a workflow, scan for hardcoded passwords, tokens, and keys, and download the workflow as JSON. Reports show node status, severity, and the file and line for each finding.

### Run locally

Install Python 3.12 and start Docker. From the repository root, run the [setup commands](#launch) in PowerShell. The first terminal starts PostgreSQL 17 and FastAPI. The second serves the static frontend. Open the [editor](http://127.0.0.1:5173) or [Swagger UI](http://127.0.0.1:8000/docs).

The editor uses FastAPI at `127.0.0.1:8000` by default. You can change the address in Settings. Local frontend requests are allowed from `localhost` and `127.0.0.1` on ports `5173` and `3000`. PostgreSQL stores data in the `postgres_data` volume, and the API creates its tables on startup. To use an existing database, skip Docker and set [`DATABASE_URL`](#database) before starting FastAPI.

### Run your first scan

1. Create the [sample ZIP](#sample-zip) or use a project supplied by the organizers. Upload only approved training projects. ZIPs are limited to 10 MiB, 40 MiB uncompressed, and 2,000 entries.
2. In the editor, select the ZIP, click **Загрузить** (Upload), then **Запустить** (Run). The starter workflow has a manual trigger, a secret scan, and a severity condition.
3. The sample produces one `high` finding at `application.properties:1`, and the condition matches. The report omits the password value. Reopen saved workflows from **Мои сценарии** (My Workflows) or download the graph from **Файл** (File).

To call the API directly, use the [requests and sample graph](#workflow-api). To bring over data from the old SQLite prototype, start PostgreSQL and run the [import](#database) before FastAPI. The import preserves IDs and skips records already imported.

The prototype uses one local workspace. Accounts, repository URL uploads, schedules, SCA, SAST, AI, and notifications are still in progress. You can save any node type in a draft. Running a workflow with a node that isn't implemented returns `422 unsupported_node`.

Coordinate API changes with the frontend and test them with synthetic data. The scanners find issues. The LLM will explain those findings. Keep API keys and tokens on the backend.

## Launch

Терминал 1 / Terminal 1:

```powershell
docker compose up -d --wait db
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Терминал 2 / Terminal 2:

```powershell
python -m http.server 5173 --bind 127.0.0.1 --directory frontend
```

## Sample ZIP

```powershell
New-Item -ItemType Directory -Path .data\training-sample -Force | Out-Null
Set-Content -Encoding ASCII -Path .data\training-sample\application.properties -Value 'demo.password=synthetic-demo-password'
Compress-Archive -Path .data\training-sample\application.properties -DestinationPath .data\training-sample.zip -Force
```

## Workflow API

| Запрос / Request | Вход и результат / Input and result |
| --- | --- |
| `POST /sources` | ZIP, `multipart/form-data`, поле / field `file` → `sourceId` |
| `POST /workflows` | JSON графа / workflow JSON → `id` |
| `GET /workflows`, `GET /workflows/{workflowId}` | Список сценариев или один граф / list workflows or get one graph |
| `PUT /workflows/{workflowId}` | Изменённый граф / updated graph → `Workflow` |
| `POST /workflows/{workflowId}/runs` | `{"sourceId":"..."}` → `202`, `runId` |
| `GET /runs/{runId}` | Проверяйте статус до / poll until `succeeded` or `failed` |

Схемы запросов и ответов / Request and response schemas — [OpenAPI JSON](http://127.0.0.1:8000/openapi.json). Ошибки / Errors — `{code, message}`.

Для графа нужен один триггер без входов. Все ноды должны быть достижимы из него, циклы запрещены. Выход условия указывается через `sourceHandle` со значением `"true"` или `"false"`. / Use one trigger with no incoming edges. Every node must be reachable from it, and the graph must be acyclic. Edges leaving a condition need a `sourceHandle` of `"true"` or `"false"`.

Пример для `POST /workflows` / Example body for `POST /workflows`:

```json
{
  "name": "Secret scan",
  "nodes": [
    {"id": "start", "type": "trigger", "position": {"x": 0, "y": 0}, "config": {"mode": "manual"}},
    {"id": "scan", "type": "secrets", "position": {"x": 240, "y": 0}, "config": {}},
    {"id": "check", "type": "condition", "position": {"x": 480, "y": 0}, "config": {"minSeverity": "high"}}
  ],
  "edges": [
    {"id": "start-scan", "source": "start", "target": "scan"},
    {"id": "scan-check", "source": "scan", "target": "check"}
  ]
}
```

## Database

Своя база / Existing PostgreSQL:

```powershell
$env:DATABASE_URL = 'postgresql://USER:PASSWORD@HOST:5432/DBNAME'
```

Пользователю БД нужны права на создание таблиц. / The database user needs permission to create tables.

Импорт из SQLite / Import from SQLite:

```powershell
.\.venv\Scripts\python.exe -m backend.import_sqlite .data/workflow.sqlite3
```

Исходный файл SQLite открывается только для чтения. / The SQLite source file is opened read-only.
