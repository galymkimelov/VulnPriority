# schemas.py — Pydantic схемы для валидации входящих данных

from enum import Enum
import re
from pydantic import BaseModel, validator, confloat, constr
from typing import List, Optional

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class VulnerabilityStatus(str, Enum):
    OPEN = "Open"
    IN_PROGRESS = "In Progress"
    PENDING_VERIFICATION = "Pending Verification"
    RESOLVED = "Resolved"
    VERIFIED = "Verified"


class VulnInput(BaseModel):
    """Одна уязвимость из загружаемого JSON-файла."""
    cve: constr(strip_whitespace=True, min_length=1)
    cvss: confloat(ge=0.0, le=10.0)
    description: Optional[str] = ""

    @validator("cve")
    def validate_cve(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not CVE_REGEX.match(normalized):
            raise ValueError("CVE должен быть в формате CVE-YYYY-NNNN")
        return normalized


class ScanInput(BaseModel):
    """Корневой формат загружаемого JSON-файла со сканом."""
    host: constr(strip_whitespace=True, min_length=1)
    vulnerabilities: List[VulnInput]

    @validator("host")
    def validate_host(cls, value: str) -> str:
        return value.strip()


class AssetUpdate(BaseModel):
    """Схема для обновления критичности актива."""
    criticality: confloat(ge=0.0, le=1.0)


class StatusUpdate(BaseModel):
    """Схема для обновления статуса уязвимости."""
    status: VulnerabilityStatus
