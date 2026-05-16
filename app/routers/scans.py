# scans.py — история сканов и сравнение (delta)

from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.templates import render_template
from app.models import Scan, Vulnerability

router = APIRouter()


@router.get("/scans", response_class=HTMLResponse)
def list_scans(request: Request, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return render_template(
        request,
        "scans.html",
        {
            "scans": scans,
        },
    )


def _scan_asset_cves(db: Session, scan_id: int) -> dict[str, set[str]]:
    rows = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan_id)
        .all()
    )
    by_asset: dict[str, set[str]] = defaultdict(set)
    for v in rows:
        asset_ip = v.asset.ip if v.asset else "—"
        if v.cve:
            by_asset[str(asset_ip)].add(str(v.cve))
    return dict(by_asset)


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    current_vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.scan_id == scan_id)
        .order_by(Vulnerability.risk_score.desc())
        .all()
    )

    # предыдущий скан (по времени)
    prev_scan = (
        db.query(Scan)
        .filter(Scan.created_at < scan.created_at)
        .order_by(Scan.created_at.desc())
        .first()
    )

    delta: dict[str, Any] = {
        "prev_scan": prev_scan,
        "new_total": 0,
        "resolved_total": 0,
        "by_asset": [],
    }

    if prev_scan:
        cur_map = _scan_asset_cves(db, scan_id)
        prev_map = _scan_asset_cves(db, prev_scan.id)

        all_assets = sorted(set(cur_map.keys()) | set(prev_map.keys()))
        by_asset_rows: list[dict[str, Any]] = []
        new_total = 0
        resolved_total = 0

        for asset in all_assets:
            cur = cur_map.get(asset, set())
            prev = prev_map.get(asset, set())

            new_cves = sorted(cur - prev)
            resolved_cves = sorted(prev - cur)

            if new_cves:
                new_total += len(new_cves)
            if resolved_cves:
                resolved_total += len(resolved_cves)

            by_asset_rows.append(
                {
                    "asset": asset,
                    "current": len(cur),
                    "previous": len(prev),
                    "new_cves": new_cves,
                    "resolved_cves": resolved_cves,
                }
            )

        delta["new_total"] = new_total
        delta["resolved_total"] = resolved_total
        delta["by_asset"] = by_asset_rows

    return render_template(
        request,
        "scan_detail.html",
        {
            "scan": scan,
            "vulnerabilities": current_vulns,
            "delta": delta,
        },
    )

