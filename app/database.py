# database.py — настройка подключения к SQLite через SQLAlchemy

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Путь к файлу базы данных SQLite
DATABASE_URL = "sqlite:///./vulnerabilities.db"

# Создаём движок БД (connect_args нужен для SQLite + многопоточности)
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Фабрика сессий — используется для работы с БД в каждом запросе
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Базовый класс для всех моделей
Base = declarative_base()


def get_db():
    """Dependency: создаёт сессию БД на время обработки запроса."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
