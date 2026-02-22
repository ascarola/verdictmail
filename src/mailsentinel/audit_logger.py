"""
audit_logger.py — SQLite audit log + rotating file logger setup.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(log_file: str, max_bytes: int, backup_count: int) -> logging.Logger:
    """Configure root logger with a RotatingFileHandler and a StreamHandler."""
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Rotating file handler
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    # Console handler (captured by systemd journal via stdout/stderr)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    return root


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id       TEXT,
    timestamp        TEXT,
    sender           TEXT,
    subject          TEXT,
    threat_level     TEXT,
    threat_types     TEXT,
    confidence       REAL,
    signals          TEXT,
    reasoning        TEXT,
    model_name       TEXT,
    action_taken     TEXT,
    processing_ms    INTEGER,
    raw_ai_response  TEXT
);
"""


def init_db(db_path: str) -> sqlite3.Connection:
    """Open (or create) the SQLite database and ensure the audit_log table exists."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(CREATE_TABLE_SQL)
    conn.commit()
    return conn


def log_decision(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
    """Insert one row into audit_log.

    Expected keys in *record*:
        message_id, timestamp, sender, subject, threat_level, threat_types,
        confidence, signals, reasoning, model_name, action_taken,
        processing_ms, raw_ai_response
    """
    sql = """
    INSERT INTO audit_log
        (message_id, timestamp, sender, subject, threat_level, threat_types,
         confidence, signals, reasoning, model_name, action_taken,
         processing_ms, raw_ai_response)
    VALUES
        (:message_id, :timestamp, :sender, :subject, :threat_level, :threat_types,
         :confidence, :signals, :reasoning, :model_name, :action_taken,
         :processing_ms, :raw_ai_response)
    """
    # Serialize list/dict fields to JSON text
    row = dict(record)
    if isinstance(row.get("threat_types"), (list, dict)):
        row["threat_types"] = json.dumps(row["threat_types"])
    if isinstance(row.get("signals"), (list, dict)):
        row["signals"] = json.dumps(row["signals"])

    with conn:
        conn.execute(sql, row)
