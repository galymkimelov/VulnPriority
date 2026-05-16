# assets.py — роутер управления активами

from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.i18n import LOCALE_COOKIE, get_locale_from_cookie, tr
from app.templates import render_template
from app.models import Asset, Vulnerability
from app.services.risk import calculate_risk

router = APIRouter()


@router.get("/assets", response_class=HTMLResponse)
def list_assets(request: Request, db: Session = Depends(get_db)):
    """
    Показывает все активы с их IP и критичностью.
    Также показывает количество уязвимостей на каждом хосте.
    """
    assets = db.query(Asset).all()

    # Получаем статистику уязвимостей для каждого актива
    for asset in assets:
        asset.vuln_count = len(asset.vulnerabilities)

    return render_template(
        request,
        "assets.html",
        {
            "assets": assets,
            "criticality_options": [1.0, 0.7, 0.4],
        },
    )


@router.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail(asset_id: int, request: Request, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.risk_score.desc())
        .all()
    )

    # Trend by scan (avg risk)
    by_scan = {}
    for v in vulns:
        sid = v.scan_id
        if not sid:
            continue
        by_scan.setdefault(sid, []).append(v.risk_score or 0.0)

    locale = get_locale_from_cookie(request.cookies.get(LOCALE_COOKIE))
    trend_labels = []
    trend_avg = []
    for sid in sorted(by_scan.keys()):
        vals = by_scan[sid]
        trend_labels.append(f"{tr(locale, 'scan_label')} #{sid}")
        trend_avg.append(round((sum(vals) / len(vals)) * 100, 2) if vals else 0.0)

    return render_template(
        request,
        "asset_detail.html",
        {
            "asset": asset,
            "vulnerabilities": vulns,
            "trend": {"labels": trend_labels, "avg_risk": trend_avg},
        },
    )


@router.post("/assets/{asset_id}/criticality")
def update_criticality(
    asset_id: int,
    criticality: float = Form(...),
    db: Session = Depends(get_db)
):
    """
    Обновляет критичность актива и пересчитывает риск-скоры
    всех связанных уязвимостей.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if asset:
        asset.criticality = criticality

        # Пересчитываем risk_score для всех уязвимостей этого актива
        for vuln in asset.vulnerabilities:
            vuln.risk_score = calculate_risk(
                cvss=vuln.cvss,
                epss=vuln.epss,
                asset_criticality=criticality,
                exploit_factor=vuln.exploit_factor,
                exposure_factor=vuln.exposure_factor,
            )

        db.commit()

    return RedirectResponse(url="/assets", status_code=303)
