from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser

import pytest

from spamreporter.analysis import analyze, parse
from spamreporter.store import Store
from spamreporter.submission import build, prepare


def test_import_dedup_and_deliveries(store, raw):
    digest = store.ingest(raw, "one", "delivery1")
    assert store.ingest(raw, "one", "delivery1") == digest
    store.ingest(raw, "two", "delivery1")
    store.ingest(raw, "one", "delivery2")
    assert store.db.execute("SELECT count(*) FROM messages").fetchone()[0] == 1
    assert store.db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 3
    assert store.ingest(raw + b"changed", "one") != digest
    assert store.message(digest)["raw"] == raw


def test_transaction_rollback(store, raw):
    digest = store.ingest(raw, "one")
    with pytest.raises(RuntimeError), store.transaction():
        store.transition(digest, "analyzed")
        raise RuntimeError()
    assert store.message(digest)["state"] == "captured"


def test_parallel_ingest(cfg, store, raw):
    def ingest(_):
        connection = Store(cfg.data_dir)
        try:
            return connection.ingest(raw, "one")
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=6) as pool:
        assert len(set(pool.map(ingest, range(18)))) == 1
    assert store.db.execute("SELECT count(*) FROM messages").fetchone()[0] == 1


def test_mime_original_bytes_and_count(raw):
    payload = build(
        [raw, raw.replace(b"body", b"second body")], "a@example.net", "submit.TESTONLY@spamcop.net"
    )
    parsed = BytesParser(policy=policy.default).parsebytes(payload)
    assert not parsed.defects
    attachments = list(parsed.iter_attachments())
    assert len(attachments) == 2
    assert all(part.get_content_type() == "message/rfc822" for part in attachments)
    assert (
        attachments[0].get_payload(0).as_bytes(policy=policy.SMTP.clone(refold_source="none"))
        == raw
    )
    assert raw in payload


def test_limits(raw):
    for originals in ([], [raw] * 21, [raw + b"x\r\n" * 25000], [raw + b"\x00"]):
        with pytest.raises(ValueError):
            build(originals, "a@example.net", "submit.TESTONLY@spamcop.net")
    assert len(build([raw] * 20, "a@example.net", "submit.TESTONLY@spamcop.net")) < 50000


def test_malformed_header():
    metadata = parse(b"not a header\n\nbody")
    assert metadata["defects"]
    assert metadata["sender_domain"] == "unknown"


def test_prepare_idempotent(store, cfg, raw):
    digest = store.ingest(raw, "one")
    analyze(store, cfg)
    store.queue(digest, "one")
    assert prepare(store, cfg, dry_run=True) == [digest]
    assert store.message(digest)["state"] == "queued"
    assert prepare(store, cfg) == [digest]
    assert prepare(store, cfg) == []
    assert store.message(digest)["state"] == "prepared"


def test_mime_limit_includes_overhead(raw):
    sender, recipient = "a@example.net", "submit.TESTONLY@spamcop.net"
    overhead = len(build([raw], sender, recipient)) - len(raw)
    target = 50_000 - overhead
    padding = target - len(raw)
    extended = raw + b"x\r\n" * (padding // 3) + b"x" * (padding % 3)
    assert len(build([extended], sender, recipient)) == 50_000
    with pytest.raises(ValueError, match="50,000"):
        build([extended + b"x"], sender, recipient)


def test_binary_safe_ingest_and_mime_8bit(store, raw):
    original = raw + b"\xff\xfe\nno trailing newline"
    digest = store.ingest(original, "one")
    assert store.message(digest)["raw"] == original
    payload = build([original], "a@example.net", "submit.TESTONLY@spamcop.net")
    assert original in payload


def test_parallel_prepare(store, cfg, raw):
    digest = store.ingest(raw, "one")
    analyze(store, cfg)
    store.queue(digest, "one")

    def attempt(_):
        connection = Store(cfg.data_dir)
        try:
            return prepare(connection, cfg)
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(len(result) for result in pool.map(attempt, range(4))) == 1
