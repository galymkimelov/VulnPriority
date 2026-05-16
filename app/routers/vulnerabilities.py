# vulnerabilities.py — роутер управления уязвимостями

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from app.templates import render_template
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Vulnerability, Asset
from app.services.risk import get_risk_level
from app.services.remediation import update_status, VALID_STATUSES

router = APIRouter()


def _severity_bucket(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


SLA_DAYS = {
    "Critical": 2,
    "High": 10,
    "Medium": 30,
    "Low": 60,
}



@router.get("/vulnerabilities", response_class=HTMLResponse)
def list_vulnerabilities(request: Request, db: Session = Depends(get_db)):
    """
    Показывает все уязвимости из БД, отсортированные по risk_score (убывание).
    Добавляет уровень риска (High/Medium/Low) для цветовой индикации.
    """
    q = (request.query_params.get("q") or "").strip()
    status = (request.query_params.get("status") or "").strip()
    severity = (request.query_params.get("severity") or "").strip()
    asset_q = (request.query_params.get("asset") or "").strip()

    try:
        page = max(int(request.query_params.get("page") or 1), 1)
    except ValueError:
        page = 1
    allowed_sizes = {8, 10, 20, 50}
    try:
        page_size = int(request.query_params.get("page_size") or 10)
    except ValueError:
        page_size = 10
    if page_size not in allowed_sizes:
        page_size = 10

    query = db.query(Vulnerability)

    if q:
        like = f"%{q}%"
        query = query.filter(or_(Vulnerability.cve.ilike(like), Vulnerability.description.ilike(like)))

    if status and status in VALID_STATUSES:
        query = query.filter(Vulnerability.status == status)

    if asset_q:
        like = f"%{asset_q}%"
        query = query.join(Asset, Vulnerability.asset_id == Asset.id).filter(Asset.ip.ilike(like))

    total_count = query.count()
    total_pages = max((total_count + page_size - 1) // page_size, 1)
    if page > total_pages:
        page = total_pages

    vulns = (
        query.order_by(Vulnerability.risk_score.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    # Добавляем уровень риска к каждому объекту (для шаблона)
    now = datetime.utcnow()
    for v in vulns:
        v.risk_level = get_risk_level(v.risk_score)
        try:
            v.severity_bucket = _severity_bucket(float(v.cvss))
        except (TypeError, ValueError):
            v.severity_bucket = "Low"

        base_dt = v.scan.created_at if getattr(v, "scan", None) and v.scan and v.scan.created_at else now
        due = base_dt + timedelta(days=SLA_DAYS.get(v.severity_bucket, 30))
        v.sla_due_iso = due.isoformat() + "Z"
        v.is_overdue = (v.status != "Fixed") and (now > due)

    if severity:
        vulns = [v for v in vulns if getattr(v, "severity_bucket", "") == severity]

    return render_template(
        request,
        "vulnerabilities.html",
        {
            "vulnerabilities": vulns,
            "statuses": VALID_STATUSES,
            "filters": {
                "q": q,
                "status": status,
                "severity": severity,
                "asset": asset_q,
                "page": page,
                "page_size": page_size,
            },
            "pagination": {
                "total": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
            },
        },
    )


@router.get("/vulnerabilities/{vuln_id}", response_class=HTMLResponse)
def vulnerability_detail(vuln_id: int, request: Request, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.risk_level = get_risk_level(vuln.risk_score)

    return render_template(
        request,
        "vulnerability_detail.html",
        {
            "vuln": vuln,
            "statuses": VALID_STATUSES,
        },
    )


@router.post("/vulnerabilities/{vuln_id}/status")
def change_status(
    vuln_id: int,
    status: str = Form(...),
    db: Session = Depends(get_db)
):
    """
    Обновляет статус уязвимости через HTML-форму (POST).
    Параметр status приходит через Form() из тела запроса.
    После обновления перенаправляет обратно на страницу уязвимостей.
    """
    update_status(db, vuln_id, status)
    return RedirectResponse(url="/vulnerabilities", status_code=303)
