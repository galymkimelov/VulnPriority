# dashboard.py — роутер дашборда со сводной статистикой

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db, engine
from app.i18n import LOCALE_COOKIE, get_locale_from_cookie, tr
from app.templates import render_template
from app.models import Vulnerability, Scan
from app.models import Base
from app.services.risk import get_risk_level

router = APIRouter()


def _severity_bucket(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    """
    Показывает сводную статистику:
    - Общее количество уязвимостей
    - Разбивка по уровням риска: High / Medium / Low
    - Разбивка по статусам: New / In Progress / Fixed
    - Топ-5 наиболее опасных уязвимостей
    """
    all_vulns = db.query(Vulnerability).all()

    # Подсчёт по уровням риска
    high = sum(1 for v in all_vulns if get_risk_level(v.risk_score) == "High")
    medium = sum(1 for v in all_vulns if get_risk_level(v.risk_score) == "Medium")
    low = sum(1 for v in all_vulns if get_risk_level(v.risk_score) == "Low")

    # Подсчёт по статусам (включая legacy-статусы и текущие статусы remediation-board)
    status_counts = {
        "New": sum(1 for v in all_vulns if v.status == "New"),
        "In Progress": sum(1 for v in all_vulns if v.status == "In Progress"),
        "Fixed": sum(1 for v in all_vulns if v.status == "Fixed"),
        "Open": sum(1 for v in all_vulns if v.status == "Open"),
        "Pending Verification": sum(1 for v in all_vulns if v.status == "Pending Verification"),
        "Resolved": sum(1 for v in all_vulns if v.status == "Resolved"),
        "Verified": sum(1 for v in all_vulns if v.status == "Verified"),
    }

    # SLA compliant: считаем закрытыми задачи в финальных статусах remediation + legacy Fixed.
    closed_for_sla = (
        status_counts["Fixed"] +
        status_counts["Resolved"] +
        status_counts["Verified"]
    )
    total_vulns = len(all_vulns)
    sla_percent = (closed_for_sla / total_vulns * 100) if total_vulns else 0

    # Топ-5 самых опасных уязвимостей
    top5 = sorted(all_vulns, key=lambda v: v.risk_score, reverse=True)[:5]
    for v in top5:
        v.risk_level = get_risk_level(v.risk_score)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in all_vulns:
        try:
            bucket = _severity_bucket(float(v.cvss))
        except (TypeError, ValueError):
            bucket = "Low"
        severity_counts[bucket] += 1

    scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(12).all()
    scans = list(reversed(scans))
    locale = get_locale_from_cookie(request.cookies.get(LOCALE_COOKIE))
    trend_labels = []
    for idx, s in enumerate(scans, 1):
        timestamp = s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "—"
        trend_labels.append(f"{idx}\n{timestamp}")
    trend_avg_risk: list[float] = []
    trend_total: list[int] = []
    for s in scans:
        rows = db.query(Vulnerability).filter(Vulnerability.scan_id == s.id).all()
        if rows:
            avg = sum(float(v.risk_score or 0.0) for v in rows) / len(rows)
        else:
            avg = 0.0
        trend_avg_risk.append(round(avg * 100, 2))
        trend_total.append(len(rows))

    return render_template(
        request,
        "dashboard.html",
        {
            "total": total_vulns,
            "high": high,
            "medium": medium,
            "low": low,
            "status_counts": status_counts,
            "sla_percent": sla_percent,
            "top5": top5,
            "critical_count": severity_counts["Critical"],
            "severity_counts": severity_counts,
            "trend": {
                "labels": trend_labels,
                "avg_risk": trend_avg_risk,
                "total": trend_total,
            },
        },
    )


@router.post("/admin/reset-db")
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return RedirectResponse(url="/dashboard", status_code=303)
