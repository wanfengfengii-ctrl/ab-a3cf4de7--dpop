"""SQLite-backed single-use store for DPoP proof jti values.

A proof is "consumed" by inserting (jkt, jti) guarded by a PRIMARY KEY, so
under any level of concurrency exactly one claim wins. The database lives on
a persistent volume, therefore a consumed proof stays consumed across
container restarts.
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time


class ReplayStore:
    def __init__(self, db_path: str, retention_seconds: int = 86400):
        self._retention = retention_seconds
        self._lock = threading.Lock()
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS used_jti (
                jkt        TEXT NOT NULL,
                jti        TEXT NOT NULL,
                iat        INTEGER NOT NULL,
                claimed_at INTEGER NOT NULL,
                PRIMARY KEY (jkt, jti)
            )
            """
        )
        self._conn.commit()
        self.purge(time.time())

    def claim(self, jkt: str, jti: str, iat: int, now: float | None = None) -> bool:
        """Atomically consume (jkt, jti). Returns False if already consumed."""
        claimed_at = int(time.time() if now is None else now)
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO used_jti (jkt, jti, iat, claimed_at) "
                    "VALUES (?, ?, ?, ?)",
                    (jkt, jti, int(iat), claimed_at),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def purge(self, now: float | None = None) -> int:
        """Drop entries older than the retention window (>= DPoP iat window)."""
        cutoff = int((time.time() if now is None else now) - self._retention)
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM used_jti WHERE claimed_at < ?", (cutoff,)
            )
            self._conn.commit()
            return cursor.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
