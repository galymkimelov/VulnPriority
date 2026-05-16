# Экспорт отчётов: CSV и PDF (язык kk / ru / en)

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.i18n import LOCALE_COOKIE, normalize_locale
from app.services.report_export import build_csv, build_pdf, fetch_vulnerability_rows, summary_counts

router = APIRouter()


def _resolve_locale(request: Request, lang: str | None) -> str:
    return normalize_locale(lang or request.cookies.get(LOCALE_COOKIE))


@router.get("/reports/vulnerabilities.csv")
def export_vulnerabilities_csv(
    request: Request,
    lang: str | None = None,
    db: Session = Depends(get_db),
):
    loc = _resolve_locale(request, lang)
    rows = fetch_vulnerability_rows(db, loc)
    body = build_csv(loc, rows)
    ascii_name = f"vulnpriority_vulnerabilities_{loc}.csv"
    disp = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(ascii_name)}'
    return Response(
        content=body,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": disp},
    )


@router.get("/reports/vulnerabilities.pdf")
def export_vulnerabilities_pdf(
    request: Request,
    lang: str | None = None,
    db: Session = Depends(get_db),
):
    loc = _resolve_locale(request, lang)
    rows = fetch_vulnerability_rows(db, loc)
    summ = summary_counts(db, rows)
    try:
        body = build_pdf(db, loc, rows, summ)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ascii_name = f"vulnpriority_report_{loc}_{day}.pdf"
    disp = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{quote(ascii_name)}'
    return Response(
        content=body,
        media_type="application/pdf",
        headers={"Content-Disposition": disp},
    )
