from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.templates import render_template
from app.models import Vulnerability, Asset
from app.services.risk import get_risk_level
from app.services.remediation import update_status, VALID_STATUSES

router = APIRouter()

BOARD_COLUMNS = ["Open", "In Progress", "Pending Verification", "Resolved", "Verified"]


@router.get("/remediation", response_class=HTMLResponse)
def remediation_board(request: Request, db: Session = Depends(get_db)):
    q = (request.query_params.get("q") or "").strip()
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
    if asset_q:
        like = f"%{asset_q}%"
        query = query.join(Asset, Vulnerability.asset_id == Asset.id).filter(Asset.ip.ilike(like))

    totals_by_status: dict[str, int] = {}
    columns: dict[str, list[Vulnerability]] = {}
    max_total = 0

    for st in BOARD_COLUMNS:
        q_st = query.filter(Vulnerability.status == st)
        total_st = q_st.count()
        totals_by_status[st] = total_st
        if total_st > max_total:
            max_total = total_st

    total_pages = max((max_total + page_size - 1) // page_size, 1)
    if page > total_pages:
        page = total_pages

    for st in BOARD_COLUMNS:
        rows = (
            query.filter(Vulnerability.status == st)
            .order_by(Vulnerability.risk_score.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        for v in rows:
            v.risk_level = get_risk_level(v.risk_score)
        columns[st] = rows
    return render_template(
        request,
        "remediation.html",
        {
            "columns": columns,
            "statuses": VALID_STATUSES,
            "filters": {
                "q": q,
                "asset": asset_q,
            },
            "pagination": {
                "total": sum(totals_by_status.values()),
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
            },
            "totals_by_status": totals_by_status,
        },
    )


@router.post("/remediation/{vuln_id}/move")
def move_card(vuln_id: int, status: str = Form(...), db: Session = Depends(get_db)):
    update_status(db, vuln_id, status)
    return RedirectResponse(url="/remediation", status_code=303)

