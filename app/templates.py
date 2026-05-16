# Единый Jinja2Templates и render с локализацией (Jinja2 >= 3.1.6)

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader

from app.i18n import (
    LOCALE_COOKIE,
    criticality_badge,
    get_locale_from_cookie,
    risk_badge_label,
    severity_label,
    status_label,
    t_bundle,
)

_jinja_env = Environment(
    loader=FileSystemLoader("templates"),
    auto_reload=True,
    cache_size=0,
)
templates = Jinja2Templates(env=_jinja_env)


def render_template(request: Request, name: str, context: dict[str, Any] | None = None) -> Any:
    ctx = dict(context or {})
    locale = get_locale_from_cookie(request.cookies.get(LOCALE_COOKIE))
    next_path = request.url.path + ("?" + request.url.query if request.url.query else "")
    switch_next = quote(next_path, safe="")

    ctx.setdefault("critical_count", 0)
    ctx.update(
        {
            "locale": locale,
            "html_lang": locale,
            "t": t_bundle(locale),
            "switch_next": switch_next,
            "ls": lambda s: status_label(locale, s),
            "lsev": lambda s: severity_label(locale, s),
            "lrisk": lambda r: risk_badge_label(locale, r),
            "lcrit_badge": lambda level: criticality_badge(locale, level),
        }
    )
    return templates.TemplateResponse(request, name, ctx)
