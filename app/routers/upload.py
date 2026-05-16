# upload.py — роутер загрузки файлов скана

import os
import shutil
import uuid
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Vulnerability, Scan
from app.services.parser import parse_scan_file
from app.services.enrichment import enrich_vulnerability
from app.services.risk import calculate_risk
from app.constants import DEFAULT_ASSET_CRITICALITY, DEFAULT_VULNERABILITY_STATUS

router = APIRouter()

# Папка для хранения загруженных файлов
UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/upload")
async def upload_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Принимает JSON файл скана, парсит его и сохраняет уязвимости в БД.
    
    Шаги:
    1. Сохранить файл на диск
    2. Распарсить JSON
    3. Найти или создать актив (Asset) по IP
    4. Для каждой уязвимости: обогатить → рассчитать риск → сохранить
    5. Перенаправить на страницу уязвимостей
    """

    # 1. Сохраняем файл в папку uploads/
    safe_filename = os.path.basename(file.filename) or f"upload-{uuid.uuid4().hex}.json"
    filepath = UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_filename}"
    with open(filepath, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # 2. Парсим JSON через сервис parser
    try:
        scans = parse_scan_file(filepath)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # 2.1 Создаём запись скана (для истории)
    scan_row = Scan(
        source_filename=file.filename,
        total_hosts=len(scans),
        total_vulns=sum(len(s.vulnerabilities) for s in scans),
    )
    db.add(scan_row)
    db.commit()
    db.refresh(scan_row)

    # 3-4. Для каждого хоста: найти/создать актив и сохранить уязвимости
    for scan in scans:
        asset = db.query(Asset).filter(Asset.ip == scan.host).first()
        if not asset:
            asset = Asset(ip=scan.host, criticality=DEFAULT_ASSET_CRITICALITY)
            db.add(asset)
            db.commit()
            db.refresh(asset)

        for vuln_data in scan.vulnerabilities:
            enriched = enrich_vulnerability(vuln_data.cve, vuln_data.cvss)

            risk_score = calculate_risk(
                cvss=vuln_data.cvss,
                epss=enriched["epss"],
                asset_criticality=asset.criticality,
                exploit_factor=enriched["exploit_factor"],
                exposure_factor=enriched["exposure_factor"],
            )

            existing_vuln = db.query(Vulnerability).filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.cve == vuln_data.cve,
                Vulnerability.scan_id == scan_row.id,
            ).first()

            if existing_vuln:
                existing_vuln.cvss = vuln_data.cvss
                existing_vuln.epss = enriched["epss"]
                existing_vuln.exploit_factor = enriched["exploit_factor"]
                existing_vuln.exposure_factor = enriched["exposure_factor"]
                existing_vuln.risk_score = risk_score
                existing_vuln.description = vuln_data.description
                existing_vuln.status = DEFAULT_VULNERABILITY_STATUS
            else:
                vuln = Vulnerability(
                    cve=vuln_data.cve,
                    cvss=vuln_data.cvss,
                    epss=enriched["epss"],
                    exploit_factor=enriched["exploit_factor"],
                    exposure_factor=enriched["exposure_factor"],
                    risk_score=risk_score,
                    description=vuln_data.description,
                    status=DEFAULT_VULNERABILITY_STATUS,
                    asset_id=asset.id,
                    scan_id=scan_row.id,
                )
                db.add(vuln)

    db.commit()

    # 5. Перенаправляем на страницу уязвимостей
    return RedirectResponse(url="/vulnerabilities", status_code=303)
