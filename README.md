# CodeBloodhound

Проект для Cyber Garden 2026 · A Cyber Garden 2026 project

[Русский](#русский) · [English](#english)

## Русский

Делаем конструктор проверок безопасности для учебных проектов на Kotlin, Spring Boot и Gradle Kotlin DSL. В редакторе можно собрать сценарий из нод, сохранить его, запустить поиск секретов, SCA и SAST и скачать схему в JSON. В отчёте видны статусы нод, критичность, файл и строка каждой находки.

### Локальный запуск

Установите Python 3.12 и запустите Docker. Из корня проекта выполните [команды запуска](#launch) в PowerShell. Первый терминал поднимает PostgreSQL 17 и FastAPI, второй раздаёт статический фронтенд. Откройте [редактор](http://127.0.0.1:5173) или [Swagger UI](http://127.0.0.1:8000/docs).

По умолчанию редактор обращается к FastAPI на `127.0.0.1:8000`. Адрес можно поменять в настройках. Для локального фронтенда разрешены `localhost` и `127.0.0.1` на портах `5173` и `3000`. PostgreSQL хранит данные в томе `postgres_data`, таблицы создаются при запуске API. Со своей базой можно пропустить команду Docker и задать [`DATABASE_URL`](#database) перед запуском FastAPI.

### Первая проверка

1. Соберите [учебный ZIP](#sample-zip) или возьмите проект организаторов. Загружайте только разрешённые учебные проекты. Лимит ZIP — 10 МиБ, после распаковки — 40 МиБ и 2000 записей.
2. В редакторе выберите ZIP, нажмите «Загрузить», затем «Запустить». Начальный сценарий уже содержит ноды запуска, поиска секретов и условия по критичности.
3. В отчёте для примера появится одна находка `high` в `application.properties:1`, а условие сработает. Значение пароля в отчёт не попадает. Сохранённый сценарий можно открыть в «Мои сценарии», а схему скачать через меню «Файл».

Для работы напрямую с API используйте [запросы и пример графа](#workflow-api). Если остались данные старого SQLite-прототипа, запустите PostgreSQL и выполните [импорт](#database) перед запуском FastAPI. Он сохранит ID архивов, сценариев и отчётов, а при повторном запуске пропустит уже перенесённые записи.

Для полной проверки загрузите учебный архив организаторов со справочником `vulnerability-database/vulnerabilities.json`. Добавьте из каталога «Анализ зависимостей» (SCA) и «Статический анализ» (SAST) и соедините их с остальным графом. SCA берёт версии из Gradle, отдаёт приоритет `gradle.lockfile` и сверяет версии с офлайн-справочником Maven. Если вы загружаете только исходники, задайте путь к справочнику через `CYBER_GARDEN_ADVISORIES` перед запуском API. SAST проверяет Kotlin по базовым правилам для SQL, TLS, CORS и прав доступа. Находки SAST требуют проверки по контексту.

Пока это одно локальное рабочее пространство. Аккаунты, загрузка по ссылке, расписание, AI-чат и уведомления ещё в работе. Черновики принимают все типы нод, а попытка запустить неподключённую ноду вернёт `422 unsupported_node`.

При разработке сверяйте изменения API с фронтендом и проверяйте их на синтетических данных. Анализаторы сами ищут проблемы. LLM будет объяснять уже найденное. Ключи и токены хранятся на бэкенде.

### Подключение LLM

Подключение к модели вынесено в `backend/llm.py`. Модуль AI-ноды вызывает `load_llm().complete(messages, json_mode=True)`, передаёт свой промпт и проверяет структуру ответа. Выберите [Ollama или DeepSeek](#llm-setup) в том же терминале, из которого запускаете FastAPI. Если провайдер недоступен, клиент возвращает `LlmError` с кодом причины.

## English

We're building a security workflow editor for training projects that use Kotlin, Spring Boot, and Gradle Kotlin DSL. You can build and save a workflow, run secret detection, SCA and SAST, and download the workflow as JSON. Reports show node status, severity, and the file and line for each finding.

### Run locally

Install Python 3.12 and start Docker. From the repository root, run the [setup commands](#launch) in PowerShell. The first terminal starts PostgreSQL 17 and FastAPI. The second serves the static frontend. Open the [editor](http://127.0.0.1:5173) or [Swagger UI](http://127.0.0.1:8000/docs).

The editor uses FastAPI at `127.0.0.1:8000` by default. You can change the address in Settings. Local frontend requests are allowed from `localhost` and `127.0.0.1` on ports `5173` and `3000`. PostgreSQL stores data in the `postgres_data` volume, and the API creates its tables on startup. To use an existing database, skip Docker and set [`DATABASE_URL`](#database) before starting FastAPI.

### Run your first scan

1. Create the [sample ZIP](#sample-zip) or use a project supplied by the organizers. Upload only approved training projects. ZIPs are limited to 10 MiB, 40 MiB uncompressed, and 2,000 entries.
2. In the editor, select the ZIP, click **Загрузить** (Upload), then **Запустить** (Run). The starter workflow has a manual trigger, a secret scan, and a severity condition.
3. The sample produces one `high` finding at `application.properties:1`, and the condition matches. The report omits the password value. Reopen saved workflows from **Мои сценарии** (My Workflows) or download the graph from **Файл** (File).

To call the API directly, use the [requests and sample graph](#workflow-api). To bring over data from the old SQLite prototype, start PostgreSQL and run the [import](#database) before FastAPI. The import preserves IDs and skips records already imported.

For a full scan, upload the organizers' training archive with `vulnerability-database/vulnerabilities.json`. Add **Анализ зависимостей** (SCA) and **Статический анализ** (SAST) from the catalog and connect them to the graph. SCA reads Gradle dependency versions, prefers `gradle.lockfile`, and checks versions against the offline Maven catalog. For a ZIP with source files only, set `CYBER_GARDEN_ADVISORIES` to the catalog path before starting the API. SAST checks Kotlin with basic rules for SQL, TLS, CORS and authorization. Review SAST findings in context.

The prototype uses one local workspace. Accounts, repository URL uploads, schedules, AI chat, and notifications are still in progress. You can save any node type in a draft. Running a workflow with a node that isn't implemented returns `422 unsupported_node`.

Coordinate API changes with the frontend and test them with synthetic data. The scanners find issues. The LLM will explain those findings. Keep API keys and tokens on the backend.

### Connect an LLM

The provider client lives in `backend/llm.py`. The AI node calls `load_llm().complete(messages, json_mode=True)` with its own prompt and validates the response structure. Choose [Ollama or DeepSeek](#llm-setup) in the terminal that starts FastAPI. If the provider is unavailable, the client raises `LlmError` with an error code.

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

## LLM setup

Локальная модель в Ollama / Local model served by Ollama:

```powershell
$env:LLM_PROVIDER = 'local'
$env:LOCAL_LLM_BASE_URL = 'http://127.0.0.1:11434/v1'
$env:LOCAL_LLM_MODEL = '<installed-model>'
```

Проверено с `qwen3:8b` (`ollama pull qwen3:8b`). Первый запрос после запуска Ollama загружает модель в память и может идти дольше минуты, поэтому для локальной модели поставьте `$env:LLM_TIMEOUT_SECONDS = '180'`. Клиент по умолчанию отправляет `reasoning_effort: "none"`: без этого Qwen3 сначала «думает», тратит сотни токенов и чаще ломает JSON. Чтобы вернуть рассуждения, задайте `LOCAL_LLM_REASONING_EFFORT` (`low`, `medium`, `high`), а пустая строка отключает параметр. / Tested with `qwen3:8b`. The first request after Ollama starts loads the model and can take over a minute, so set `LLM_TIMEOUT_SECONDS` to `180` for a local model. The client sends `reasoning_effort: "none"` by default; override it with `LOCAL_LLM_REASONING_EFFORT`, or set it to an empty string to omit it.

Укажите название установленной модели. Для другого OpenAI-совместимого сервера задайте его базовый URL и, если нужен ключ, `LOCAL_LLM_API_KEY`. / Use the installed model's name. For another OpenAI-compatible server, set its base URL and `LOCAL_LLM_API_KEY` if it requires authentication. [Ollama API](https://docs.ollama.com/api/openai-compatibility)

DeepSeek API:

```powershell
$env:LLM_PROVIDER = 'deepseek'
$env:DEEPSEEK_MODEL = 'deepseek-flash'
$env:DEEPSEEK_API_KEY = [Net.NetworkCredential]::new('', (Read-Host 'DeepSeek API key' -AsSecureString)).Password
```

Провайдер выбирается через `LLM_PROVIDER`. Таймаут по умолчанию — 60 секунд, его можно изменить через `LLM_TIMEOUT_SECONDS`. / Select the provider with `LLM_PROVIDER`. The default timeout is 60 seconds. Override it with `LLM_TIMEOUT_SECONDS`. [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)

Пример вызова из AI-ноды / Example call from the AI node:

```python
from backend.llm import load_llm

messages = [{"role": "user", "content": 'Return a JSON object with "status" set to "ok".'}]
answer = load_llm().complete(messages, json_mode=True)
```

### AI-нода / AI node

Нода `ai` (`backend/ai.py`) отправляет модели до 15 самых критичных находок из входящих связей и записывает ответ в `aiAnalysis` отчёта. Находки получают короткие ссылки `F1`, `F2`…, а рекомендации с неизвестными или повторяющимися ссылками отбрасываются. Ответ проверяется по схеме, при сломанном JSON делается один повтор. Если модель недоступна, нода завершается со статусом `succeeded`, `output.aiAvailable = false` и текстом причины в `error`, а находки идут дальше по графу. / The `ai` node sends up to 15 of the most severe incoming findings to the model and stores the answer in the report's `aiAnalysis`. Recommendations must reference a finding that was sent. If the model is unavailable, the node still succeeds with `output.aiAvailable = false` and the findings continue through the graph.

Тесты / Tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -t .
```
