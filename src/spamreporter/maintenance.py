"""Retention removes sensitive data but keeps deduplication tombstones."""

from datetime import UTC, datetime, timedelta

from .config import Config, private_dir
from .store import Store


def cleanup(store: Store, cfg: Config, dry_run: bool = False) -> int:
    expired = []
    now = datetime.now(UTC)
    with store.transaction():
        for row in store.db.execute("SELECT hash,created,state FROM messages WHERE purged=0"):
            sources = store.db.execute(
                "SELECT DISTINCT source FROM deliveries WHERE hash=?", (row["hash"],)
            ).fetchall()
            # All copies expire at the longest applicable retention period.
            days = max(
                (
                    cfg.sources[s["source"]].retention_days if s["source"] in cfg.sources else 30
                    for s in sources
                ),
                default=30,
            )
            if datetime.fromisoformat(row["created"]) + timedelta(days=days) > now:
                continue
            # Never remove the attachment while an editor or transport owns it.
            if row["state"] in {"handing_off", "draft_opened"}:
                continue
            expired.append(row["hash"])
            if dry_run:
                continue
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
    if not dry_run:
        store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return len(expired)
