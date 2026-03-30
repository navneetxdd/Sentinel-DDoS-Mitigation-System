"""
Shared helpers: migrate plain SQLite sentinel_events.db to SQLCipher.
Used by scripts/migrate_sentinel_events_to_sqlcipher.py and explain_api bootstrap.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any


def is_plain_sqlite(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(15) == b"SQLite format 3"
    except OSError:
        return False


def migrate_plain_to_sqlcipher_file(plain_path: str, out_path: str, passphrase: str) -> int:
    """
    Read plain_path (SQLite), write encrypted database to out_path.
    Returns number of rows migrated. Raises on verification failure or missing deps.
    """
    try:
        import sqlcipher3.dbapi2 as sc  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            "sqlcipher3 is not installed; pip install sqlcipher3 (requires SQLCipher libraries on the host)."
        ) from e

    if not os.path.isfile(plain_path):
        raise FileNotFoundError(plain_path)
    if not is_plain_sqlite(plain_path):
        raise ValueError(f"Not a plain SQLite file: {plain_path}")

    src = sqlite3.connect(f"file:{plain_path}?mode=ro", uri=True, timeout=60.0)
    try:
        rows = src.execute(
            "SELECT id, event_ts, logged_at, payload FROM sentinel_events ORDER BY id"
        ).fetchall()
    finally:
        src.close()

    esc = passphrase.replace("'", "''")
    if os.path.exists(out_path):
        os.remove(out_path)

    dst = sc.connect(out_path, check_same_thread=False, timeout=60.0)
    try:
        dst.execute(f"PRAGMA key = '{esc}'")
        dst.execute("PRAGMA journal_mode=WAL")
        dst.execute("PRAGMA synchronous=NORMAL")
        dst.execute(
            """
            CREATE TABLE sentinel_events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                event_ts  REAL    NOT NULL,
                logged_at TEXT    NOT NULL,
                payload   TEXT    NOT NULL
            )
            """
        )
        dst.execute("CREATE INDEX idx_event_ts ON sentinel_events (event_ts DESC)")
        dst.executemany(
            "INSERT INTO sentinel_events (id, event_ts, logged_at, payload) VALUES (?, ?, ?, ?)",
            rows,
        )
        if rows:
            max_id = max(int(r[0]) for r in rows)
            dst.execute("DELETE FROM sqlite_sequence WHERE name = 'sentinel_events'")
            dst.execute(
                "INSERT INTO sqlite_sequence (name, seq) VALUES ('sentinel_events', ?)",
                (max_id,),
            )
        dst.commit()
    finally:
        dst.close()

    verify = sc.connect(out_path, check_same_thread=False, timeout=60.0)
    try:
        verify.execute(f"PRAGMA key = '{esc}'")
        n: Any = verify.execute("SELECT COUNT(1) FROM sentinel_events").fetchone()[0]
    finally:
        verify.close()

    if int(n) != len(rows):
        raise RuntimeError(f"SQLCipher verify failed: expected {len(rows)} rows, got {n}")
    return len(rows)
