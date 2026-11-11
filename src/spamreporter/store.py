"""Transactional content identity, deliveries and an auditable state machine."""

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .config import private_dir

STATES = {
    "captured",
    "analyzed",
    "queued",
    "prepared",
    "handing_off",
    "handed_off",
    "draft_opened",
    "response_received",
    "completed",
    "error",
    "manual_review",
}


class Store:
    def __init__(self, directory: Path):
        private_dir(directory)
        path = directory / "state.sqlite3"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if path.stat().st_mode & 0o077:
            raise ValueError("Database must have mode 0600")
        self.db = sqlite3.connect(path, timeout=15, isolation_level=None)
        if self.db.execute("PRAGMA user_version").fetchone()[0] not in {0, 1}:
            self.db.close()
            raise ValueError("Unsupported database schema version; use a compatible release")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                hash TEXT PRIMARY KEY, raw BLOB, state TEXT NOT NULL DEFAULT 'captured',
                created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                metadata TEXT NOT NULL DEFAULT '{}', approved_source TEXT,
                error TEXT, purged INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS deliveries (
                id INTEGER PRIMARY KEY, hash TEXT NOT NULL REFERENCES messages(hash),
                source TEXT NOT NULL, delivery_key TEXT NOT NULL,
                created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                UNIQUE(source, delivery_key, hash)
            );
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL REFERENCES messages(hash),
                payload BLOB, sender TEXT NOT NULL, recipient TEXT NOT NULL,
                backend TEXT, attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, hash TEXT NOT NULL REFERENCES messages(hash),
                state TEXT NOT NULL, detail TEXT NOT NULL,
                created TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY, hash TEXT NOT NULL REFERENCES messages(hash),
                digest TEXT NOT NULL, raw BLOB NOT NULL, kind TEXT NOT NULL
            );
            PRAGMA user_version=1;
        """)

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield self.db
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def transition(self, digest: str, state: str, detail: str = "") -> None:
        if state not in STATES:
            raise ValueError("Unknown processing state")
        self.db.execute(
            "UPDATE messages SET state=?,error=? WHERE hash=?",
            (state, detail if state in {"error", "manual_review"} else None, digest),
        )
        self.db.execute(
            "INSERT INTO events(hash,state,detail) VALUES(?,?,?)", (digest, state, detail)
        )

    def ingest(self, raw: bytes, source: str, key: str = "", limit: int = 10_000_000) -> str:
        if not raw or len(raw) > limit:
            raise ValueError("Empty message or input size limit exceeded")
        digest = hashlib.sha256(raw).hexdigest()
        with self.transaction():
            inserted = self.db.execute(
                "INSERT OR IGNORE INTO messages(hash,raw) VALUES(?,?)", (digest, raw)
            ).rowcount
            if inserted:
                self.transition(digest, "captured")
            self.db.execute(
                "INSERT OR IGNORE INTO deliveries(hash,source,delivery_key) VALUES(?,?,?)",
                (digest, source, key or digest),
            )
        return digest

    def message(self, digest: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM messages WHERE hash=?", (digest,)).fetchone()
        if row is None:
            raise ValueError("Unknown message fingerprint (use the full SHA-256)")
        return row

    def queue(self, digest: str, source: str) -> None:
        with self.transaction():
            row = self.message(digest)
            if row["purged"] or row["state"] != "analyzed":
                raise ValueError("Only analyzed, retained messages can be queued")
            if not self.db.execute(
                "SELECT 1 FROM deliveries WHERE hash=? AND source=?", (digest, source)
            ).fetchone():
                raise ValueError("Message was not observed in that source")
            self.db.execute("UPDATE messages SET approved_source=? WHERE hash=?", (source, digest))
            self.transition(digest, "queued", "User reviewed unsolicited bulk email")

    def metadata(self, digest: str, value: dict) -> None:
        self.db.execute(
            "UPDATE messages SET metadata=? WHERE hash=?",
            (json.dumps(value, ensure_ascii=True), digest),
        )
