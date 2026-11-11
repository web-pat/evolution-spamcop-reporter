"""Durable, silent Evolution intake, independent of SQLite write locks."""

import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime

from .config import Config, private_dir, private_write
from .inputs import read_file
from .store import Store


def capture(cfg: Config, raw: bytes, source: str, delivery_id: str = "") -> None:
    cfg.source(source)
    if not raw or len(raw) > cfg.max_input_bytes:
        raise ValueError("Empty message or input size limit exceeded")
    private_dir(cfg.data_dir)
    directory = cfg.data_dir / "intake"
    private_dir(directory)
    key = hashlib.sha256(delivery_id.encode()).hexdigest() if delivery_id else ""
    record = {
        "source": source,
        "key": key,
        "captured": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "raw": base64.b64encode(raw).decode("ascii"),
    }
    name = uuid.uuid4().hex
    temporary, ready = directory / f"{name}.tmp", directory / f"{name}.json"
    try:
        private_write(temporary, json.dumps(record).encode("ascii"))
        os.replace(temporary, ready)
        for folder in (directory, cfg.data_dir):
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def drain(store: Store, cfg: Config) -> tuple[int, int]:
    """Commit before unlink; replay after a crash is idempotent, including parallel drains."""
    directory = cfg.data_dir / "intake"
    if not directory.exists():
        return 0, 0
    private_dir(directory)
    count, failures = 0, 0
    for path in sorted(directory.glob("*.json")):
        try:
            record = json.loads(read_file(path, 140_000_000))
            source, key, captured = record["source"], record["key"], record["captured"]
            if not all(isinstance(value, str) for value in (source, key, captured)):
                raise ValueError("Invalid intake metadata")
            stamp = datetime.fromisoformat(captured)
            if stamp.tzinfo is None:
                raise ValueError("Intake timestamp must have a timezone")
            raw = base64.b64decode(record["raw"], validate=True)
        except FileNotFoundError:
            continue  # Another consumer committed and removed this record.
        except (ValueError, TypeError, KeyError, OSError):
            failures += 1  # Keep corrupt/unreadable records for local diagnosis.
            continue
        # Source changes after capture must not silently discard already accepted mail.
        store.ingest(raw, source, key, limit=100_000_000, captured=captured)
        path.unlink(missing_ok=True)
        count += 1
    return count, failures
