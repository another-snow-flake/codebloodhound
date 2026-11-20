# CodeBloodhound

Проект для Cyber Garden 2026 · A Cyber Garden 2026 project

[Русский](#русский) · [English](#english)

## Русский

Делаем конструктор проверок безопасности для учебных проектов на Kotlin, Spring Boot и Gradle Kotlin DSL. В редакторе можно собрать сценарий из нод, сохранить его, запустить поиск секретов, SCA и SAST и скачать схему в JSON. В отчёте видны статусы нод, критичность, файл и строка каждой находки.

### Статус проекта

Обновлено 20 ноября 2026.

- Работают ручной запуск, три анализатора, условие по критичности, отчёт, AI-рекомендации и чат по отчёту.
- AI показывает этапы работы и группирует рекомендации. Топ действий считается по критичности, а CVE для разных версий одной библиотеки идут в отдельные карточки.
- Webhook отправляет находки и AI-рекомендации из активной ветки. Доставка проверена в Edge на локальном HTTP-приёмнике с 15 находками из учебного архива.
- Модель для AI выбирается в настройках редактора отдельно в каждой вкладке: локальные модели из Ollama или DeepSeek. Модель передаётся с запуском и вопросом в чате и фиксируется до начала работы, согласие на DeepSeek проверяет сервер. Перед сменой выполняется проверочный запрос, и если он не проходит, остаётся прежняя модель. Проверено в Chrome на двух вкладках одновременно (qwen3:8b и DeepSeek) и с не скачанной моделью. DeepSeek проверяли через локальную заглушку с тем же API, на реальном ключе не проверяли.
- Локальную модель можно отдать бэкенду на другом компьютере через `tools/start_remote_llm.ps1`: шлюз с ключом и SSH-туннель. Скрипт останавливает только свои процессы, токен хранится в одном файле с доступом только для владельца и не попадает в вывод и логи. Шлюз ограничивает соединения и время чтения запроса. Проверено через публичный адрес: старый токен `401`, новый работает, служебный API Ollama закрыт, AI-нода отвечает.
- Весь сайт можно показать с одного компьютера через `tools/start_site.ps1`: портативный PostgreSQL, FastAPI, редактор за паролем и публичная ссылка. Проверено через публичный адрес: без пароля `401`, сценарий с поиском секретов, SAST и AI прошёл за 13–15 с, чат ответил, данные сохранились в PostgreSQL.
- До сдачи остаются расписание, дополнительные условия и экспорт находок в формате организаторов.

После каждого крупного изменения обновляйте этот блок в том же коммите. Запишите, что заработало, как это проверили и что осталось. Так другой чат или участник команды сможет продолжить с актуального состояния.

### Локальный запуск

Установите Python 3.12 и запустите Docker. Из корня проекта выполните [команды запуска](#launch) в PowerShell. Первый терминал поднимает PostgreSQL 17 и FastAPI, второй раздаёт статический фронтенд. Откройте [редактор](http://127.0.0.1:5173) или [Swagger UI](http://127.0.0.1:8000/docs).

По умолчанию редактор обращается к FastAPI на `127.0.0.1:8000`. Адрес можно поменять в настройках. Для локального фронтенда разрешены `localhost` и `127.0.0.1` на портах `5173` и `3000`. PostgreSQL хранит данные в томе `postgres_data`, таблицы создаются при запуске API. Со своей базой можно пропустить команду Docker и задать [`DATABASE_URL`](#database) перед запуском FastAPI.

### Первая проверка

1. Соберите [учебный ZIP](#sample-zip) или возьмите проект организаторов. Загружайте только разрешённые учебные проекты. Лимит ZIP — 10 МиБ, после распаковки — 40 МиБ и 2000 записей.
2. В редакторе выберите ZIP, нажмите «Загрузить», затем «Запустить». Начальный сценарий уже содержит ноды запуска, поиска секретов и условия по критичности.
3. В отчёте для примера появится одна находка `high` в `application.properties:1`, а условие сработает. Значение пароля в отчёт не попадает. Сохранённый сценарий можно открыть в «Мои сценарии», а схему скачать через меню «Файл».

Для работы напрямую с API используйте [запросы и пример графа](#workflow-api). Если остались данные старого SQLite-прототипа, запустите PostgreSQL и выполните [импорт](#database) перед запуском FastAPI. Он сохранит ID архивов, сценариев и отчётов, а при повторном запуске пропустит уже перенесённые записи.

Для полной проверки загрузите учебный архив организаторов со справочником `vulnerability-database/vulnerabilities.json`. Добавьте из каталога «Анализ зависимостей» (SCA) и «Статический анализ» (SAST) и соедините их с остальным графом. SCA берёт версии из Gradle, отдаёт приоритет `gradle.lockfile` и сверяет версии с офлайн-справочником Maven. Если вы загружаете только исходники, задайте путь к справочнику через `CYBER_GARDEN_ADVISORIES` перед запуском API. SAST проверяет Kotlin по базовым правилам для SQL, TLS, CORS и прав доступа. Находки SAST требуют проверки по контексту.

Пока это одно локальное рабочее пространство. Аккаунты, загрузка по ссылке и запуск по расписанию ещё в работе.

При разработке сверяйте изменения API с фронтендом и проверяйте их на синтетических данных. Анализаторы сами ищут проблемы. LLM будет объяснять уже найденное. Ключи и токены хранятся на бэкенде.

### Подключение LLM

Подключение к модели вынесено в `backend/llm.py`. Модуль AI-ноды вызывает `load_llm().complete(messages, json_mode=True)`, передаёт свой промпт и проверяет структуру ответа. Выберите [Ollama или DeepSeek](#llm-setup) в том же терминале, из которого запускаете FastAPI. Если провайдер недоступен, клиент возвращает `LlmError` с кодом причины.

После завершения проверки можно задать вопрос справа. Чат использует до 15 наиболее серьёзных находок и последние сообщения по этому запуску. Для чата достаточно готового отчёта и настроенной модели, нода «AI-рекомендации» нужна для автоматического резюме.

### Уведомления

Настройте [получателя HTTP webhook](#webhook) перед запуском API. В редакторе добавьте «Уведомление», выберите получателя и подключите ноду к выходу «да» после условия. Например, отправляйте отчёт, только если есть высокие или критические находки. Получатель получит данные из активной ветки.

## English

We're building a security workflow editor for training projects that use Kotlin, Spring Boot, and Gradle Kotlin DSL. You can build and save a workflow, run secret detection, SCA and SAST, and download the workflow as JSON. Reports show node status, severity, and the file and line for each finding.

### Project status

Updated November 20, 2026.

- Manual runs, all three scanners, severity branching, reports, AI recommendations, and report chat work.
- The AI panel shows processing stages and groups recommendations. Priorities are ranked by severity, and CVEs for different versions of the same dependency get separate cards.
- The webhook sends findings and AI recommendations from the active branch. Delivery was tested in Edge with a local HTTP receiver and 15 findings from the training archive.
- The AI model is chosen per browser tab: local Ollama models or DeepSeek. Each run and chat message carries its model, pinned before work starts; the server checks consent for DeepSeek. A synthetic check runs before a switch, and a failed check keeps the previous model. Tested in Chrome with two tabs at once (qwen3:8b and DeepSeek) and with a model that isn't downloaded. DeepSeek was tested against a local stub, not a real key.
- A remote backend can use this PC's local model through `tools/start_remote_llm.ps1`: an authenticated gateway plus an SSH tunnel. The script stops only its own processes; the token lives in one owner-only file and never appears in output or logs. The gateway limits connections and request read time. Tested through the public URL: old token 401, new token works, Ollama's own API blocked.
- The whole site can be shown from one PC with `tools/start_site.ps1`: portable PostgreSQL, FastAPI, the editor behind a password and a public link. Tested through the public URL: 401 without the password, a run with secrets, SAST and AI took 13–15 s, chat answered, data persisted in PostgreSQL.
- Scheduled runs, additional conditions, and exporting findings in the organizers' format are still pending.

Update this section in the same commit as each major change. Record what works, how it was verified, and what remains so the next chat or teammate can pick up from here.

### Run locally

Install Python 3.12 and start Docker. From the repository root, run the [setup commands](#launch) in PowerShell. The first terminal starts PostgreSQL 17 and FastAPI. The second serves the static frontend. Open the [editor](http://127.0.0.1:5173) or [Swagger UI](http://127.0.0.1:8000/docs).

The editor uses FastAPI at `127.0.0.1:8000` by default. You can change the address in Settings. Local frontend requests are allowed from `localhost` and `127.0.0.1` on ports `5173` and `3000`. PostgreSQL stores data in the `postgres_data` volume, and the API creates its tables on startup. To use an existing database, skip Docker and set [`DATABASE_URL`](#database) before starting FastAPI.

### Run your first scan

1. Create the [sample ZIP](#sample-zip) or use a project supplied by the organizers. Upload only approved training projects. ZIPs are limited to 10 MiB, 40 MiB uncompressed, and 2,000 entries.
2. In the editor, select the ZIP, click **Загрузить** (Upload), then **Запустить** (Run). The starter workflow has a manual trigger, a secret scan, and a severity condition.
3. The sample produces one `high` finding at `application.properties:1`, and the condition matches. The report omits the password value. Reopen saved workflows from **Мои сценарии** (My Workflows) or download the graph from **Файл** (File).

To call the API directly, use the [requests and sample graph](#workflow-api). To bring over data from the old SQLite prototype, start PostgreSQL and run the [import](#database) before FastAPI. The import preserves IDs and skips records already imported.

For a full scan, upload the organizers' training archive with `vulnerability-database/vulnerabilities.json`. Add **Анализ зависимостей** (SCA) and **Статический анализ** (SAST) from the catalog and connect them to the graph. SCA reads Gradle dependency versions, prefers `gradle.lockfile`, and checks versions against the offline Maven catalog. For a ZIP with source files only, set `CYBER_GARDEN_ADVISORIES` to the catalog path before starting the API. SAST checks Kotlin with basic rules for SQL, TLS, CORS and authorization. Review SAST findings in context.

The prototype uses one local workspace. Accounts, repository URL uploads, and scheduled runs are still in progress.

Coordinate API changes with the frontend and test them with synthetic data. The scanners find issues. The LLM will explain those findings. Keep API keys and tokens on the backend.

### Connect an LLM

The provider client lives in `backend/llm.py`. The AI node calls `load_llm().complete(messages, json_mode=True)` with its own prompt and validates the response structure. Choose [Ollama or DeepSeek](#llm-setup) in the terminal that starts FastAPI. If the provider is unavailable, the client raises `LlmError` with an error code.

Ask a question in the right panel after a scan finishes. Chat uses up to 15 of the most severe findings and recent messages from that run. A finished report and a configured model are enough for chat. Add the AI node to generate an automatic summary.

### Notifications

Configure an [HTTP webhook recipient](#webhook) before starting the API. In the editor, add **Уведомление** (Notification), select the recipient, and connect the node to the condition's **да** (Yes) output. For example, send the report only when there are high or critical findings. The recipient gets data from the active branch.

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

## Show the site

Чтобы показать сайт команде с одного компьютера, на нём должны быть Ollama, `.venv` и портативный PostgreSQL 17 в `%LOCALAPPDATA%\codebloodhound-site\pg17` с базой в `pgdata`. Docker не нужен. Запуск и остановка:

```powershell
powershell -ExecutionPolicy Bypass -File tools\start_site.ps1        # запустить или перезапустить
powershell -ExecutionPolicy Bypass -File tools\start_site.ps1 -Url   # текущий адрес: localhost.run его периодически меняет
powershell -ExecutionPolicy Bypass -File tools\start_site.ps1 -Stop  # остановить всё
```

Скрипт поднимает PostgreSQL, FastAPI с локальной моделью, `tools/serve_site.py` и SSH-туннель через localhost.run. Он печатает адрес, имя пользователя `team` и путь к файлу с паролем. Сам пароль на экран не выводится: его нужно открыть в `site-password.txt`.

- `serve_site.py` отдаёт `frontend/` и пересылает `/api/*` в FastAPI. Страница и API на одном адресе, поэтому CORS менять не нужно, а редактор сам находит API по пути `/api`.
- Весь сайт закрыт HTTP Basic. В API уходят только `Content-Type` и `Accept`, методы ограничены `GET`, `POST` и `PUT`. Не больше 32 соединений, на чтение запроса 30 секунд, тело до 11 МиБ.
- Логи лежат в `%LOCALAPPDATA%\codebloodhound-site\logs`: `site.log` (метод, путь и статус каждого запроса), `api.err.log` (uvicorn и ошибки FastAPI), `postgres.log`, `tunnel.log`. Тела запросов и пароли в логи не пишутся. Через туннель адрес посетителя не виден, во всех строках будет `127.0.0.1`.
- Два анонимных туннеля localhost.run с одного компьютера могут получить один адрес. Поэтому `start_site.ps1` останавливает туннель модели из `start_remote_llm.ps1`: сайту он не нужен, бэкенд ходит в Ollama напрямую.

To demo the whole site from one PC, run `tools\start_site.ps1` (`-Url` prints the current address, `-Stop` stops everything). It starts PostgreSQL, FastAPI with the local model, `tools/serve_site.py` (the editor and `/api` on one origin, behind HTTP Basic with user `team`) and a localhost.run tunnel, and prints the URL and the password file path. Logs are in `%LOCALAPPDATA%\codebloodhound-site\logs`.

## Workflow API

| Запрос / Request | Вход и результат / Input and result |
| --- | --- |
| `POST /sources` | ZIP, `multipart/form-data`, поле / field `file` → `sourceId` |
| `POST /workflows` | JSON графа / workflow JSON → `id` |
| `GET /workflows`, `GET /workflows/{workflowId}` | Список сценариев или один граф / list workflows or get one graph |
| `PUT /workflows/{workflowId}` | Изменённый граф / updated graph → `Workflow` |
| `POST /workflows/{workflowId}/runs` | `{"sourceId":"..."}` → `202`, `runId` |
| `GET /runs/{runId}` | Проверяйте статус до / poll until `succeeded` or `failed` |
| `POST /runs/{runId}/chat` | `{"question":"...","history":[]}` → `{"answer":"...","model":"local:qwen3:8b"}` |
| `GET /settings/llm` | Модели, их статус и модель сервера по умолчанию / models, their status, and the server default |
| `POST /settings/llm/check` | `{"modelId":"local:qwen3:8b","allowExternal":false}` → `{ok, seconds}` или `{ok:false, code}` / synthetic connection check |
| `GET /webhooks` | Список имён получателей / list of recipient names |

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

## Webhook

Настройте адрес получателя в окружении FastAPI. Адрес ниже — пример локального приёмника, замените его адресом своего сервиса, принимающего HTTP POST с JSON. / Configure the recipient URL in the FastAPI environment. Replace the local example below with a service that accepts HTTP POST with JSON.

```powershell
$env:CYBER_GARDEN_WEBHOOKS = '{"demo":"http://127.0.0.1:9000/report"}'
```

Нода хранит имя `config.webhookRef`, в примере это `demo`. Запрос содержит `runId`, `workflowId`, `nodeId`, `findings` и `aiAnalyses` с указанием ID AI-ноды. HTTP 2xx отмечается как доставка. При ошибке нода показывает причину, а отчёт с находками остаётся доступен.

The node stores the recipient name in `config.webhookRef` (`demo` above). The request contains `runId`, `workflowId`, `nodeId`, `findings`, and `aiAnalyses` tagged with their AI node IDs. HTTP 2xx marks delivery as successful. On delivery failure, the node shows the reason and the findings remain in the report.

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

### Выбор модели в редакторе / Choosing the model in the editor

`LLM_PROVIDER` задаёт модель сервера по умолчанию. В настройках редактора (⚙) можно выбрать другую: выбор хранится в `sessionStorage` вкладки, и разные вкладки не влияют друг на друга. Модель уходит на бэкенд полями `modelId` и `allowExternal` в `POST /workflows/{id}/runs` и `POST /runs/{id}/chat`. Сервер фиксирует её до начала работы, так что смена во время ответа влияет только на следующие запросы. Без `modelId` используется модель сервера. Для DeepSeek сервер требует `allowExternal: true` (согласие на отправку находок) и отвечает `403 consent_required` без него. Перед сменой редактор вызывает `POST /settings/llm/check`: синтетический запрос без данных проекта различает отклонённый ключ (`auth_error`), недоступный сервер (`connection_error`) и отсутствующую модель (`model_missing`). Если проверка не прошла, остаётся прежняя модель. Локальные модели бэкенд запрашивает у сервера по `LOCAL_LLM_BASE_URL` (`/v1/models`) и добавляет к ним список `LOCAL_LLM_MODELS` через запятую. Модели DeepSeek задаёт `DEEPSEEK_MODELS` (по умолчанию `DEEPSEEK_MODEL`). Ключи в редактор не передаются. Для Qwen3 4B берите `qwen3:4b-instruct`: тег `qwen3:4b` в Ollama ведёт на Thinking-версию, у которой рассуждения не отключаются и попадают в ответ. `DEEPSEEK_BASE_URL` (по умолчанию `https://api.deepseek.com`) нужен только для тестов с заглушкой.

`LLM_PROVIDER` sets the server's default model. The editor settings (⚙) choose another one per browser tab (`sessionStorage`). Runs and chat messages send `modelId` and `allowExternal`; the server pins the model before work starts, so a switch mid-answer only affects later requests. DeepSeek requires `allowExternal: true` and returns `403 consent_required` without it. Before switching, the editor calls `POST /settings/llm/check`, a synthetic request that tells `auth_error`, `connection_error` and `model_missing` apart; a failed check keeps the previous model. Local models come from `LOCAL_LLM_BASE_URL` (`/v1/models`) plus `LOCAL_LLM_MODELS`; DeepSeek models from `DEEPSEEK_MODELS`. For Qwen3 4B use `qwen3:4b-instruct`: the `qwen3:4b` tag is the Thinking variant, whose reasoning can't be turned off.

### Модель на другом компьютере / Model on another computer

Если бэкенд работает на одном компьютере, а видеокарта с Ollama стоит на другом, на компьютере с моделью выполните:

```powershell
powershell -ExecutionPolicy Bypass -File tools\start_remote_llm.ps1
```

Скрипт запускает `tools/llm_gateway.py` и SSH-туннель через localhost.run, печатает адрес для `LOCAL_LLM_BASE_URL` и путь к файлу с ключом для `LOCAL_LLM_API_KEY`. Сам ключ на экран не выводится. Задайте оба значения в окружении бэкенда перед запуском FastAPI вместе с `LLM_PROVIDER = 'local'` и `LOCAL_LLM_MODEL`, после этого локальные модели появятся в настройках редактора. При перезапуске скрипт останавливает только процессы, PID которых он сохранил сам, поэтому чужие SSH-туннели не трогает.

- Шлюз слушает только `127.0.0.1` и требует ключ. Он пропускает только `GET /v1/models` и `POST /v1/chat/completions` без потоковой передачи, а служебный API Ollama (скачивание и удаление моделей) снаружи закрыт. Одновременно обрабатывается не больше двух запросов.
- Ключ хранится только в `%LOCALAPPDATA%\codebloodhound-llm\token.txt`. Права на файл есть только у текущего пользователя, в git, вывод и логи ключ не попадает. Новый ключ выпускает `start_remote_llm.ps1 -RotateToken`. Текущий адрес лежит в `tunnel-url.txt` рядом.
- Шлюз держит не больше 16 открытых соединений. Каждое чтение и всё тело запроса должны уложиться в 15 секунд, иначе соединение закрывается с `408`.
- Бесплатный туннель получает новый адрес при каждом запуске скрипта, и адрес на бэкенде нужно обновить. Трафик расшифровывается на серверах localhost.run, поэтому передавайте через туннель только учебные данные. Туннели Cloudflare в нашей сети не подключаются: TLS-соединение с их сервером обрывается.

If the backend runs on one computer and Ollama on another, run `tools\start_remote_llm.ps1` on the model's computer. It starts an authenticated gateway (only `/v1/models` and non-streaming `/v1/chat/completions`, at most two requests at a time) and an SSH tunnel through localhost.run, then prints the URL and the path of the owner-only token file (the token itself is never printed or logged). Restarts stop only processes whose PIDs the script saved. The gateway allows at most 16 open connections and drops requests not received within 15 seconds. The free tunnel gets a new URL on every start, and localhost.run can see the traffic, so send only training data through it.

Провайдер выбирается через `LLM_PROVIDER`. Таймаут по умолчанию — 60 секунд, его можно изменить через `LLM_TIMEOUT_SECONDS`. / Select the provider with `LLM_PROVIDER`. The default timeout is 60 seconds. Override it with `LLM_TIMEOUT_SECONDS`. [DeepSeek Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/)

Пример вызова из AI-ноды / Example call from the AI node:

```python
from backend.llm import load_llm

messages = [{"role": "user", "content": 'Return a JSON object with "status" set to "ok".'}]
answer = load_llm().complete(messages, json_mode=True)
```

### AI-нода / AI node

Нода `ai` (`backend/ai.py`) группирует входящие находки по общему исправлению: одна версия зависимости со всеми её CVE или одно правило SAST/secrets. Модели уходят до 15 самых критичных групп со ссылками `G1`, `G2`… Она возвращает итог в 1–2 предложениях, до трёх приоритетных действий и по карточке на группу: название, действие и объяснение. Карточки с неизвестными ссылками отбрасываются, а критичность, число находок и файлов в обосновании считает сервер по отчёту. Рядом остаются `recommendations` по каждой находке, как в контракте. При сломанном JSON делается один повтор. Пока нода работает, `output.stage` проходит этапы `preparing` → `waiting` → `validating` → `done`, редактор показывает их в AI-панели. Если модель недоступна, нода завершается со статусом `succeeded`, `output.aiAvailable = false` и причиной в `error`, а находки идут дальше по графу. / The `ai` node groups findings by dependency and version or by scanner rule, then sends up to 15 of the most severe groups to the model. It returns a short summary, up to three priorities, and one card per group; `recommendations` per finding are kept for the contract. While it runs, `output.stage` moves through `preparing`, `waiting`, `validating`, and `done`. If the model is unavailable, the node still succeeds with `output.aiAvailable = false` and the findings continue through the graph.

Тесты / Tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -t .
```
