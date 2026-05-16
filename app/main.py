# main.py — точка входа FastAPI приложения

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse

from app.database import engine, Base
from app.services.schema_migrations import ensure_schema
from app.routers import upload, vulnerabilities, assets, dashboard, scans, remediation, reports
from app.i18n import LOCALE_COOKIE, normalize_locale
from app.templates import render_template

# Создаём все таблицы в БД при старте (если не существуют)
Base.metadata.create_all(bind=engine)
ensure_schema(engine)

# Инициализируем FastAPI приложение
app = FastAPI(
    title="VulnPriority — Система управления уязвимостями",
    description="MVP платформа для приоритизации уязвимостей в IT-инфраструктуре",
    version="1.0.0",
)

# Подключаем статические файлы (CSS)
static_dir = Path(__file__).resolve().parent.parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Подключаем все роутеры
app.include_router(upload.router)
app.include_router(vulnerabilities.router)
app.include_router(assets.router)
app.include_router(dashboard.router)
app.include_router(scans.router)
app.include_router(remediation.router)
app.include_router(reports.router)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Главная страница с формой загрузки файла скана."""
    return render_template(request, "index.html")


@app.get("/set-language/{lang}")
def set_language(lang: str, request: Request, next: str | None = None):
    """Сохраняет язык в cookie и возвращает на текущую страницу."""
    locale = normalize_locale(lang)
    target = next if next else "/dashboard"
    if not target.startswith("/") or target.startswith("//"):
        target = "/dashboard"
    response = RedirectResponse(url=target, status_code=303)
    response.set_cookie(
        LOCALE_COOKIE,
        locale,
        max_age=365 * 24 * 3600,
        path="/",
        httponly=False,
        samesite="lax",
    )
    return response
