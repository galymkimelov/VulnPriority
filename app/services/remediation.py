# remediation.py — сервис управления статусами уязвимостей

from sqlalchemy.orm import Session
from app.models import Vulnerability
from app.constants import VALID_STATUSES


def update_status(db: Session, vuln_id: int, new_status: str) -> Vulnerability | None:
    """
    Обновляет статус уязвимости по её ID.
    
    Возвращает обновлённый объект или None если уязвимость не найдена.
    Бросает ValueError если статус недопустим.
    """
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Недопустимый статус. Допустимые: {VALID_STATUSES}")

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if vuln is None:
        return None

    vuln.status = new_status
    db.commit()
    db.refresh(vuln)
    return vuln
