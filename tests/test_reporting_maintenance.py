import csv
import io
import json

from spamreporter.analysis import analyze
from spamreporter.maintenance import cleanup
from spamreporter.reporting import render_csv, render_html, tables, terminal
from spamreporter.submission import prepare
from spamreporter.transports import send


def test_report_counts_privacy_and_escaping(store, cfg, raw):
    digest = store.ingest(raw, "one")
    store.ingest(raw, "two")
    analyze(store, cfg)
    metadata = json.loads(store.message(digest)["metadata"])
    metadata["origins"]["one"].update({"operator": "<script>bad</script>", "asn": "=1+1"})
    with store.transaction():
        store.metadata(digest, metadata)
    document = render_html(store, cfg)
    assert "<script>" not in document
    assert "&lt;script&gt;" in document
    assert "recipient@example.net" not in document
    assert cfg.recipient not in document
    assert "not global spam statistics" in document
    records = list(csv.DictReader(io.StringIO(render_csv(store, cfg))))
    assert len(records) == 2
    assert records[0]["asn"] == "'=1+1"
    assert records[0]["mailbox_domain"] == "unknown"
    assert "IP observations" in terminal(store, cfg)
    states = tables(store, cfg)["Unique message states (including retention tombstones)"]
    assert ["analyzed", "1"] in states


def test_empty_reports(store, cfg):
    assert "Local spam observations" in render_html(store, cfg)
    assert "fingerprint" in render_csv(store, cfg)
    assert "Attribution provenance" in terminal(store, cfg)


def test_cleanup_retains_dedup_history(store, cfg, raw):
    digest = store.ingest(raw, "one", "delivery-a")
    store.ingest(raw, "one", "delivery-b")
    analyze(store, cfg)
    store.queue(digest, "one")
    prepare(store, cfg)
    send(store, cfg, digest)
    store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    assert cleanup(store, cfg, dry_run=True) == 1
    assert store.message(digest)["raw"] == raw
    assert cleanup(store, cfg) == 1
    assert store.message(digest)["raw"] is None
    assert not (cfg.data_dir / "outbox" / f"{digest}.eml").exists()
    assert store.ingest(raw, "one", "delivery-a") == digest
    assert store.message(digest)["raw"] is None
    assert store.message(digest)["state"] == "expired"


def test_cleanup_keeps_active_draft(store, cfg, raw):
    digest = store.ingest(raw, "one")
    with store.transaction():
        store.transition(digest, "draft_opened")
        store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    assert cleanup(store, cfg) == 0
