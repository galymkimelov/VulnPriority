# models.py — SQLAlchemy модели (таблицы БД)

from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime


class Scan(Base):
    """
    Модель скана (одно событие импорта результатов).
    Нужна для истории и сравнения "текущий vs предыдущий".
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    source_filename = Column(String, default="")
    total_hosts = Column(Integer, default=0)
    total_vulns = Column(Integer, default=0)

    vulnerabilities = relationship("Vulnerability", back_populates="scan")


class Asset(Base):
    """
    Модель актива — хост в инфраструктуре.
    Хранит IP-адрес и критичность актива.
    """
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True)        # IP-адрес хоста
    criticality = Column(Float, default=1.0)            # Критичность: 1.0 / 0.7 / 0.4

    # Связь один-ко-многим: у одного актива может быть много уязвимостей
    vulnerabilities = relationship("Vulnerability", back_populates="asset")


class Vulnerability(Base):
    """
    Модель уязвимости.
    Хранит данные CVE, метрики риска и текущий статус.
    """
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("asset_id", "cve", "scan_id", name="uq_asset_cve_scan"),
    )

    id = Column(Integer, primary_key=True, index=True)
    cve = Column(String, index=True)                    # Идентификатор CVE
    cvss = Column(Float)                                # Базовая оценка CVSS (0–10)
    epss = Column(Float, default=0.0)                   # Вероятность эксплуатации (mock)
    exploit_factor = Column(Float, default=0.7)         # Наличие публичного эксплойта
    exposure_factor = Column(Float, default=1.0)        # Степень экспозиции хоста
    risk_score = Column(Float, default=0.0)             # Итоговый риск-скор (0–1)
    description = Column(String, default="")            # Описание уязвимости
    status = Column(String, default="New")              # Статус: New / In Progress / Fixed

    # Внешний ключ: привязка к активу
    asset_id = Column(Integer, ForeignKey("assets.id"))
    asset = relationship("Asset", back_populates="vulnerabilities")

    # Внешний ключ: привязка к скану (история)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    scan = relationship("Scan", back_populates="vulnerabilities")
