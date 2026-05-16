from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine


def _has_column(engine: Engine, table: str, column: str) -> bool:
    with engine.connect() as conn:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    # PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
    return any(r[1] == column for r in rows)


def ensure_schema(engine: Engine) -> None:
    """
    Lightweight SQLite migrations for local demo DB.
    SQLite doesn't auto-add columns on Base.metadata.create_all(), so we patch
    older databases in-place to keep the app working for диплом/demo.
    """
    # Add vulnerabilities.scan_id if missing
    if not _has_column(engine, "vulnerabilities", "scan_id"):
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN scan_id INTEGER"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vulnerabilities_scan_id ON vulnerabilities (scan_id)"))

    # Normalize legacy statuses to the current workflow
    with engine.begin() as conn:
        conn.execute(text("UPDATE vulnerabilities SET status='Open' WHERE status='New'"))
        conn.execute(text("UPDATE vulnerabilities SET status='Resolved' WHERE status='Fixed'"))

