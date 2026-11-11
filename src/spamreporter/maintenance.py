"""Retention removes sensitive data but keeps deduplication tombstones."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

from .config import Config, private_dir
from .reporting import observation
from .store import Store


def eligible(store: Store, cfg: Config, row: sqlite3.Row | None, now: datetime) -> bool:
    if row is None or row["purged"] or row["state"] in {"handing_off", "draft_opened"}:
        return False
    sources = store.db.execute(
        "SELECT DISTINCT source FROM deliveries WHERE hash=?", (row["hash"],)
    ).fetchall()
    days = max(
        (
            cfg.sources[s["source"]].retention_days if s["source"] in cfg.sources else 30
            for s in sources
        ),
        default=30,
    )
    return datetime.fromisoformat(row["created"]) + timedelta(days=days) <= now


def cleanup(store: Store, cfg: Config, dry_run: bool = False) -> int:
    expired = []
    now = datetime.now(UTC)
    candidates = store.db.execute(
        "SELECT hash,created,state,purged FROM messages WHERE purged=0"
    ).fetchall()
    for candidate in candidates:
        if not eligible(store, cfg, candidate, now):
            continue
        if dry_run:
            expired.append(candidate["hash"])
            continue
        # One bounded record per transaction, not a lock across the whole archive.
        with store.transaction():
            row = store.db.execute(
                "SELECT hash,created,state,purged FROM messages WHERE hash=?", (candidate["hash"],)
            ).fetchone()
            # Recheck: a transport may have claimed it since the read-only selection.
            if not eligible(store, cfg, row, now):
                continue
            expired.append(row["hash"])
            if cfg.retain_statistics:
                for delivery in store.db.execute(
                    "SELECT d.id,d.created,d.source,m.hash,m.state,m.metadata FROM deliveries d "
                    "JOIN messages m ON m.hash=d.hash WHERE m.hash=?",
                    (row["hash"],),
                ).fetchall():
                    store.db.execute(
                        "INSERT OR REPLACE INTO observations(delivery_id,data) VALUES(?,?)",
                        (delivery["id"], json.dumps(observation(delivery, cfg))),
                    )
            for subdir in ("outbox", "draft-attachments", "review"):
                directory = cfg.data_dir / subdir
                if directory.exists():
                    private_dir(directory)
                    (directory / f"{row['hash']}.eml").unlink(missing_ok=True)
            store.db.execute(
                "UPDATE messages SET raw=NULL,metadata='{}',purged=1 WHERE hash=?", (row["hash"],)
            )
            store.db.execute(
                "UPDATE submissions SET payload=NULL,sender='',recipient='' WHERE hash=?",
                (row["hash"],),
            )
            store.db.execute("DELETE FROM evidence WHERE hash=?", (row["hash"],))
            if row["state"] in {"captured", "analyzed", "queued", "prepared", "error"}:
                store.transition(row["hash"], "expired", "Retention expired; fingerprint retained")
    if not dry_run:
        # Do not wait on readers or writers just to reclaim WAL space.
        store.db.execute("PRAGMA wal_checkpoint(PASSIVE)")
    return len(expired)
