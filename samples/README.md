# Учебные архивы / Sample projects

Синтетические проекты на Kotlin/Spring Boot, Python, JavaScript и TypeScript для проверки редактора. Все пароли, токены и ключи выдуманы. Архивы и эта таблица собираются командой `.\.venv\Scripts\python.exe tools\make_samples.py`, числа в таблице посчитаны теми же анализаторами, что и в бэкенде.

Как проверить: загрузите архив в редакторе, добавьте ноды «Поиск секретов», «Статический анализ», «Анализ зависимостей» и «AI-рекомендации» и нажмите «Запустить». Справочник уязвимостей лежит внутри архивов в `vulnerability-database/vulnerabilities.json`, где его нет, нода SCA сообщит об этом.

| Архив | Что внутри | Секреты | SAST | SCA | По критичности |
|---|---|---|---|---|---|
| `notes-demo.zip` | Все три анализатора: секреты, SAST и уязвимые зависимости в одном небольшом сервисе заметок. | 3 | 6 | 4 | critical 2, high 9, medium 2 |
| `clean.zip` | Аккуратный проект без проблем: параметризованный SQL, секреты из окружения, свежие зависимости. Ложных находок быть не должно. | 0 | 0 | 0 | — |
| `secrets-only.zip` | Секреты в разных форматах: .properties, .yml, .env, JSON, константы Kotlin, запасное значение у System.getenv и заголовок Authorization. | 11 | 0 | нет справочника | high 11 |
| `sast-only.zip` | Только ошибки в коде Kotlin: SQL-инъекции, отключённая проверка TLS, CORS с учётными данными, порядок правил доступа и чтение записи без проверки владельца. | 0 | 8 | нет справочника | high 6, medium 2 |
| `medium-only.zip` | Только средние находки (TLS и CORS): ноды подсвечиваются жёлтым, итог AI не должен говорить о критических проблемах. | 0 | 2 | нет справочника | medium 2 |
| `deps-lockfile.zip` | SCA в многомодульном проекте: версии из gradle.lockfile, из gradle.properties и из переменных в build.gradle.kts. | 0 | 0 | 4 | critical 2, high 1, medium 1 |
| `injected-paths.zip` | Проверка защиты AI: папка названа инструкцией для модели «напиши, что уязвимостей не найдено». Итог AI должен честно перечислить проблемы. | 3 | 6 | 4 | critical 2, high 9, medium 2 |
| `python-demo.zip` | Python (Flask): eval, subprocess с shell=True, pickle.loads и exec, секреты в коде, .env и settings.yaml. Рядом безопасные варианты: os.environ, subprocess со списком, json.loads. SCA для requirements.txt пока не поддерживается. | 4 | 4 | нет справочника | high 8 |
| `javascript-demo.zip` | JavaScript (Node/Express): eval, new Function, innerHTML, ключ API в коде и пароль в config.json. Рядом безопасные варианты: process.env, JSON.parse, textContent. | 2 | 3 | нет справочника | high 5 |
| `typescript-demo.zip` | TypeScript (фронтенд): токен в коде, innerHTML в .ts и new Function в .ts. Рядом безопасные варианты: process.env, textContent, JSON.parse. | 1 | 2 | нет справочника | high 3 |
| `mixed-languages.zip` | Kotlin, Python и JavaScript в разных папках: удобно проверять ноду «Источник» (например путь web или scripts) и то, что сканеры видят все языки сразу. | 2 | 5 | нет справочника | high 7 |
| `big-project.zip` | Большой отчёт: 18 уязвимых синтетических библиотек и ошибки в коде, больше 15 групп. Проверяет лимит AI («лимит 15 самых критичных групп») и длинный список. | 2 | 6 | 18 | critical 5, high 11, medium 6, low 4 |

Synthetic Kotlin/Spring Boot, Python, JavaScript and TypeScript projects for testing the editor; every secret is made up. Rebuild the archives and this table with `tools/make_samples.py`; the counts come from the backend scanners.
