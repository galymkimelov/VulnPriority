# VulnPriority

**Система управления и приоритизации уязвимостей** - веб-приложение (MVP) для загрузки результатов сканирования, расчёта риска, учёта активов и формирования отчётов.

© 2026 **Кимелов Галым Бауыржанович**. Все права защищены.  
Программа для ЭВМ «VulnPriority» - дипломный проект.

---

## Возможности

- загрузка JSON-отчётов сканирования;
- парсинг уязвимостей (CVE, CVSS, описание);
- обогащение данных и расчёт интегрального **risk score**;
- дашборд со сводной статистикой;
- реестр **активов** (IP) с настройкой критичности;
- список и карточки **уязвимостей**, смена статуса;
- история **сканов**;
- доска **remediation** (статусы обработки);
- экспорт отчётов в **CSV** и **PDF**;
- интерфейс на **русском**, **казахском** и **английском**.

## Стек

- Python 3.11+
- [FastAPI](https://fastapi.tiangolo.com/) + [Uvicorn](https://www.uvicorn.org/)
- [SQLAlchemy](https://www.sqlalchemy.org/) + SQLite
- [Jinja2](https://jinja.palletsprojects.com/) (HTML-шаблоны)
- [ReportLab](https://www.reportlab.com/) (PDF)

## Структура проекта

```
VulnPriority/
├── app/
│   ├── main.py              # точка входа FastAPI
│   ├── models.py, schemas.py, database.py
│   ├── routers/             # маршруты (страницы и API)
│   └── services/            # парсинг, риск, отчёты, remediation
├── templates/               # HTML-шаблоны
├── static/                  # CSS
├── uploads/                 # загруженные файлы (создаётся автоматически)
├── sample_scan.json         # пример входного JSON
├── requirements.txt
└── vulnerabilities.db       # БД SQLite (создаётся при первом запуске)
```

Папки `uploads/` и файл `vulnerabilities.db` не должны попадать в git (см. `.gitignore`).

## Установка и запуск

```bash
# клонирование репозитория
git clone <url-репозитория>
cd VulnPriority

# виртуальное окружение (рекомендуется)
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate   # Linux / macOS

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Откройте в браузере: **http://127.0.0.1:8000**

Документация API (Swagger): **http://127.0.0.1:8000/docs**

## Быстрый старт

1. На главной странице загрузите файл **`sample_scan.json`** из корня репозитория.
2. Перейдите в **Dashboard** - появится сводка по уязвимостям.
3. Разделы **Vulnerabilities**, **Assets**, **Scans**, **Remediation** - для работы с данными.
4. Экспорт: `/reports/vulnerabilities.csv` и `/reports/vulnerabilities.pdf`.

## Формат входного JSON (пример)

```json
{
  "host": "192.168.1.10",
  "vulnerabilities": [
    {
      "cve": "CVE-2021-44228",
      "cvss": 10.0,
      "description": "Log4Shell: Remote Code Execution in Apache Log4j2"
    }
  ]
}
```

Поддерживаются и другие форматы (массив хостов, отчёты с полем `scan_info` и т.п.) - см. `app/services/parser.py`.