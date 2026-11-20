# Cyber Garden 2026

Локальный бэкенд конструктора проверок учебных Kotlin/Spring Boot-проектов. Роли команды и полный контракт v0 описаны в [AGENTS.md](AGENTS.md).

## Запуск в PowerShell

Из корня проекта, с Python 3.12 и запущенным Docker:

```powershell
docker compose up -d --wait db
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload
```

Бэкенд создаёт таблицы при запуске. Локальный PostgreSQL доступен на `127.0.0.1:5432`. Данные сохраняются в Docker-томе `postgres_data`. Если используете свой PostgreSQL, пропустите команду Docker и задайте `$env:DATABASE_URL = 'postgresql://USER:PASSWORD@HOST:5432/DBNAME'` перед запуском бэкенда. Пользователю БД нужны права создания таблиц.

Swagger UI доступен по адресу `http://127.0.0.1:8000/docs`, OpenAPI — по `http://127.0.0.1:8000/openapi.json`. Для локального фронтенда разрешены `localhost` и `127.0.0.1` на портах `3000` и `5173`. Бэкенд пока работает локально в одном процессе, в общем рабочем пространстве без аккаунтов.

### Перенос данных из старого прототипа

Если у вас есть `.data/workflow.sqlite3`, запустите PostgreSQL и выполните импорт перед запуском FastAPI:

```powershell
.\.venv\Scripts\python.exe -m backend.import_sqlite .data/workflow.sqlite3
```

Импорт переносит архивы, сценарии и отчёты с их ID. Исходный файл открывается только для чтения. Повторный импорт пропускает записи, которые уже есть в PostgreSQL.

## Первый прогон

1. В `POST /sources` загрузите ZIP с учебным проектом через поле `file`. Для проверки можно положить в архив `application.properties` со строкой `demo.password=synthetic-demo-password`.
2. В `POST /workflows` отправьте следующий граф и сохраните `id` из ответа.

```json
{
  "name": "Поиск секретов в учебном проекте",
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

3. Вызовите `POST /workflows/{workflowId}/runs` с `{ "sourceId": "<ID из первого шага>" }`. API вернёт `202` и `runId`.
4. Опрашивайте `GET /runs/{runId}` до `succeeded` или `failed`. Для примера выше ожидается одна находка `high` с файлом и номером строки, а нода `check` вернёт `matched: true`. Само значение секрета в отчёт не попадает.

Сценарии можно читать и обновлять через `GET /workflows`, `GET /workflows/{workflowId}` и `PUT /workflows/{workflowId}`. Ошибки API возвращаются в формате `{ "code": "...", "message": "..." }`. Поиск секретов сейчас основан на простых шаблонах присваивания и покрывает учебные примеры. ZIP ограничен 10 МиБ, 40 МиБ распакованных данных и 2000 записями.

Загрузка по ссылке, расписание, SCA, SAST, AI и уведомления пока не подключены. Черновики уже принимают все типы нод из контракта. При запуске графа с ещё не подключённой нодой API возвращает `422` с кодом `unsupported_node`.
