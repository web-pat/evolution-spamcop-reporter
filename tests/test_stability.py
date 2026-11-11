"""Regression coverage for Evolution contracts and long-running local operation."""

import csv
import hashlib
import io
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import monotonic
from types import SimpleNamespace

import pytest

from spamreporter import analysis
from spamreporter.analysis import ASNTable, analyze, origin, parse
from spamreporter.cli import dispatch, parser
from spamreporter.config import Source, config_path, data_path, load
from spamreporter.inputs import scan
from spamreporter.intake import capture, drain
from spamreporter.maintenance import cleanup
from spamreporter.reporting import render_csv
from spamreporter.store import Store
from spamreporter.submission import build, prepare, wire_size
from spamreporter.transports import launch_evolution, record_evidence, send


def ready(store, cfg, raw):
    digest = store.ingest(raw, "one")
    analyze(store, cfg)
    store.queue(digest, "one")
    prepare(store, cfg)
    return digest


def test_stdin_does_not_wait_for_database_lock(tmp_path, raw):
    config = tmp_path / "config.toml"
    data = tmp_path / "data"
    config.write_text(f'data_dir={json.dumps(str(data))}\n[[sources]]\nname="one"\n')
    config.chmod(0o600)
    store = Store(data)
    try:
        with store.transaction():
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "spamreporter.cli",
                    "--config",
                    str(config),
                    "ingest",
                    "--stdin",
                    "--source",
                    "one",
                ],
                input=raw,
                capture_output=True,
                timeout=5,
                check=True,
                env={**os.environ, "PYTHONPATH": str(Path("src").resolve())},
            )
            assert result.stdout == b""
            assert store.db.execute("SELECT count(*) FROM messages").fetchone()[0] == 0
        assert drain(store, load(config)) == (1, 0)
        assert store.message(hashlib.sha256(raw).hexdigest())["raw"] == raw
    finally:
        store.close()


def test_intake_replay_after_commit_before_unlink(store, cfg, raw, monkeypatch):
    capture(cfg, raw, "one", "delivery1")
    real_unlink = Path.unlink

    def interrupted(path, *args, **kwargs):
        if path.suffix == ".json":
            raise OSError("simulated unlink interruption")
        return real_unlink(path, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(Path, "unlink", interrupted)
        with pytest.raises(OSError):
            drain(store, cfg)
    assert drain(store, cfg) == (1, 0)
    assert store.db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 1


def test_parallel_intake_consumers(store, cfg, raw):
    for _ in range(8):
        capture(cfg, raw, "one", "same-delivery")

    def consume(_):
        other = Store(cfg.data_dir)
        try:
            return drain(other, cfg)
        finally:
            other.close()

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(consume, range(3)))
    assert store.db.execute("SELECT count(*) FROM deliveries").fetchone()[0] == 1
    assert not list((cfg.data_dir / "intake").glob("*.json"))


def test_corrupt_intake_does_not_drop_good_work(store, cfg, raw):
    capture(cfg, raw, "one")
    bad = cfg.data_dir / "intake" / "invalid.json"
    bad.write_text("not json")
    assert drain(store, cfg) == (1, 1)
    assert bad.exists()


def test_out_of_order_intake_keeps_first_capture_time(store, raw):
    late, early = "2026-11-11T12:00:00.000Z", "2026-11-11T10:00:00.000Z"
    digest = store.ingest(raw, "one", captured=late)
    store.ingest(raw, "one", captured=early)
    assert store.message(digest)["created"] == early
    assert store.db.execute("SELECT created FROM deliveries").fetchone()[0] == early


def test_cold_evolution_launch_never_killed(monkeypatch):
    class Desktop:
        def wait(self, timeout):
            raise subprocess.TimeoutExpired("evolution", timeout)

        def kill(self):
            pytest.fail("Must not kill Evolution")

        def terminate(self):
            pytest.fail("Must not terminate Evolution")

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: Desktop())
    assert launch_evolution(["evolution", "mailto:submit.TESTONLY@spamcop.net"]) is None


@pytest.mark.parametrize("code,expected", [(0, "draft_opened"), (1, "manual_review")])
def test_evolution_immediate_exit_state(store, cfg, raw, monkeypatch, code, expected):
    digest = ready(store, cfg, raw)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: SimpleNamespace(wait=lambda timeout: code)
    )
    assert send(store, cfg, digest, backend="evolution", confirm=True) == expected


def test_linear_received_handling():
    # The former regex took seconds/minutes on much smaller inputs.
    start = monotonic()
    raw = b"Received: from sender.example " + b" " * 8000 + b"no-receiver\r\n\r\nbody"
    assert origin(parse(raw)["received"], {})["ip"] == "unknown"
    assert monotonic() - start < 2


@pytest.mark.parametrize("receiver", ["mx.example@evil.example", "mx.example/evil"])
def test_receiver_requires_complete_hostname(receiver):
    assert (
        origin([f"from sender.example ([8.8.8.8]) by {receiver}; date"], {"mx.example": []})["ip"]
        == "unknown"
    )


@pytest.mark.parametrize("peer", ["224.0.0.1", "ff02::1"])
def test_multicast_not_an_origin(peer):
    assert (
        origin([f"from sender.example ([{peer}]) by mx.example; date"], {"mx.example": []})["ip"]
        == "unknown"
    )


def test_comment_cannot_supply_trust_anchor():
    header = "from sender.example ([8.8.8.8] by mx.example) by evil.example; date"
    assert origin([header], {"mx.example": []})["ip"] == "unknown"


def test_parse_runs_outside_write_lock(store, cfg, raw, monkeypatch):
    store.ingest(raw, "one")
    original = analysis.parse

    def parse_with_concurrent_import(message):
        other = Store(cfg.data_dir)
        try:
            other.db.execute("PRAGMA busy_timeout=1")
            other.ingest(raw + b"second", "two")
        finally:
            other.close()
        return original(message)

    monkeypatch.setattr(analysis, "parse", parse_with_concurrent_import)
    assert analyze(store, cfg) == 1


def test_no_write_lock_or_blob_read_for_unchanged_analysis(store, cfg, raw):
    store.ingest(raw, "one")
    analyze(store, cfg)
    queries = []
    store.db.set_trace_callback(queries.append)
    assert analyze(store, cfg) == 0
    assert not any("BEGIN IMMEDIATE" in query or "SELECT *" in query for query in queries)


def test_cleanup_does_not_lock_unexpired_records(store, cfg, raw):
    store.ingest(raw, "one")
    queries = []
    store.db.set_trace_callback(queries.append)
    assert cleanup(store, cfg) == 0
    assert not any("BEGIN IMMEDIATE" in query for query in queries)


def test_concurrent_retention_not_overwritten(store, cfg, raw, monkeypatch):
    digest = store.ingest(raw, "one")
    store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    original = analysis.parse

    def expire_during_parse(message):
        cleanup(store, cfg)
        return original(message)

    monkeypatch.setattr(analysis, "parse", expire_during_parse)
    assert analyze(store, cfg) == 0
    assert store.message(digest)["metadata"] == "{}"
    assert store.message(digest)["state"] == "expired"


def test_scan_continues_after_bad_files(tmp_path, raw):
    (tmp_path / "a.eml").write_bytes(b"")
    (tmp_path / "b.eml").write_bytes(raw)
    (tmp_path / "c.eml").write_bytes(b"x" * 2000)
    (tmp_path / "d.eml").write_bytes(raw)
    failures = []
    records = list(scan(Source("one", "eml", str(tmp_path)), 1000, failures.append))
    assert len(records) == len(failures) == 2


def test_scan_partial_failure_status(store, cfg, tmp_path, raw, capsys):
    folder = tmp_path / "mail"
    folder.mkdir()
    (folder / "bad.eml").write_bytes(b"")
    (folder / "good.eml").write_bytes(raw)
    cfg.sources["one"] = Source("one", "eml", str(folder))
    assert dispatch(parser().parse_args(["scan"]), cfg, store) == 2
    assert store.db.execute("SELECT count(*) FROM messages").fetchone()[0] == 1
    assert "skipped" in capsys.readouterr().err
    assert "SuccessExitStatus=2" in Path("systemd/spamreporter-scan.service").read_text()


def test_auto_send_skips_legacy_purged_prepared(store, cfg, raw, monkeypatch):
    expired = ready(store, cfg, raw)
    store.db.execute("UPDATE messages SET purged=1,raw=NULL WHERE hash=?", (expired,))
    store.db.execute("UPDATE submissions SET payload=NULL WHERE hash=?", (expired,))
    good = ready(store, cfg, raw + b"second")
    cfg.allow_send = cfg.allow_automatic = cfg.sources["one"].auto_submit = True
    calls = []

    def local_fake(*args, **kwargs):
        calls.append(1)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", local_fake)
    assert (
        dispatch(parser().parse_args(["send", "--backend", "sendmail", "--automatic"]), cfg, store)
        == 0
    )
    assert store.message(good)["state"] == "handed_off"
    assert len(calls) == 1


def test_lf_size_budget_without_changing_original():
    raw = b"From: a@example.org\n\n" + b"x\n" * 24000
    with pytest.raises(ValueError, match="CRLF"):
        build([raw], "a@example.net", "submit.TESTONLY@spamcop.net")
    small = b"From: a@example.org\n\n" + b"x\n" * 500
    payload = build([small], "a@example.net", "submit.TESTONLY@spamcop.net")
    assert small in payload
    assert wire_size(payload) == len(payload.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))


def test_legacy_unsafe_payload_is_rechecked_at_handoff(store, cfg, raw, monkeypatch):
    digest = ready(store, cfg, raw)
    # A legacy envelope can fit on disk but exceed the limit after SMTP normalization.
    store.db.execute("UPDATE submissions SET payload=? WHERE hash=?", (b"x\n" * 24000, digest))
    cfg.allow_send = True
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Transport invoked"))
    with pytest.raises(ValueError, match="size limit"):
        send(store, cfg, digest, backend="sendmail", confirm=True)


def test_export_handoff_evidence_blocks_resend(store, cfg, raw):
    digest = ready(store, cfg, raw)
    with pytest.raises(ValueError, match="exporting"):
        record_evidence(store, digest, "handed_off", b"synthetic receipt")
    send(store, cfg, digest, backend="eml")
    record_evidence(store, digest, "handed_off", b"synthetic receipt")
    with pytest.raises(ValueError):
        send(store, cfg, digest, backend="eml")


def test_cancelled_draft_can_expire_without_being_resent(store, cfg, raw, monkeypatch):
    digest = ready(store, cfg, raw)
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: SimpleNamespace(wait=lambda timeout: 0)
    )
    send(store, cfg, digest, backend="evolution", confirm=True)
    store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    assert cleanup(store, cfg) == 0
    record_evidence(store, digest, "cancelled", b"Verified synthetic draft closed and discarded")
    assert cleanup(store, cfg) == 1
    assert store.message(digest)["state"] == "cancelled"
    with pytest.raises(ValueError):
        send(store, cfg, digest, backend="eml", retry=True)


def test_relative_paths_are_config_relative(tmp_path, monkeypatch):
    config = tmp_path / "config.toml"
    config.write_text(
        'data_dir="data"\nasn_csv="asn.csv"\nsendmail=["./bin/mail"]\n'
        '[[sources]]\nname="one"\nkind="eml"\npath="mail"\n'
    )
    config.chmod(0o600)
    before = load(config)
    monkeypatch.chdir(tmp_path.parent)
    after = load(config)
    assert before == after
    assert after.data_dir == tmp_path / "data"
    assert after.sources["one"].path == str(tmp_path / "mail")
    assert after.asn_csv == str(tmp_path / "asn.csv")
    assert after.sendmail[0] == str(tmp_path / "bin/mail")


def test_relative_xdg_values_ignored(monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative")
    monkeypatch.setenv("XDG_DATA_HOME", "relative")
    assert config_path() == Path.home() / ".config/spamreporter/config.toml"
    assert data_path() == Path.home() / ".local/share/spamreporter"


def test_header_defects_prevent_queueing(store, cfg):
    raw = b"From: a@example.org\r\nDate: invalid\r\nMessage-ID: invalid\r\n\r\nbody"
    digest = store.ingest(raw, "one")
    analyze(store, cfg)
    assert store.message(digest)["state"] == "manual_review"
    defects = json.loads(store.message(digest)["metadata"])["defects"]
    assert "InvalidDateDefect" in defects
    assert "InvalidHeaderDefect" in defects


@pytest.mark.parametrize(
    "contents",
    [
        "prefix,owner\n1.0.0.0/8,Someone\n",
        "network,asn,operator\n8.8.8.0/24,AS64500\n",
        "network,asn,operator\n8.8.8.0/24,INVALID,Example\n",
        'network,asn,operator\n"unterminated',
    ],
)
def test_bad_asn_csv_gives_actionable_error(tmp_path, contents):
    path = tmp_path / "asn.csv"
    path.write_text(contents)
    with pytest.raises(ValueError, match="Invalid ASN CSV at line"):
        ASNTable(str(path))


def test_opt_in_history_survives_retention_without_private_headers(store, cfg, raw):
    cfg.retain_statistics = True
    digest = ready(store, cfg, raw)
    store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    before = list(csv.DictReader(io.StringIO(render_csv(store, cfg))))
    assert cleanup(store, cfg) == 1
    after = list(csv.DictReader(io.StringIO(render_csv(store, cfg))))
    assert after[0]["ip"] == before[0]["ip"]
    assert after[0]["captured_utc"] == before[0]["captured_utc"]
    assert after[0]["state"] == "expired"
    assert store.message(digest)["metadata"] == "{}"
    history = store.db.execute("SELECT data FROM observations").fetchone()[0]
    assert "recipient@example.net" not in history
    assert "Received:" not in history
    assert cleanup(store, cfg) == 0
    assert len(list(csv.DictReader(io.StringIO(render_csv(store, cfg))))) == 1


def test_full_purge_removes_opt_in_history(store, cfg, raw):
    cfg.retain_statistics = True
    ready(store, cfg, raw)
    store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    cleanup(store, cfg)
    assert dispatch(parser().parse_args(["cleanup", "--purge-all", "--confirm"]), cfg, store) == 0
    assert store.db.execute("SELECT count(*) FROM observations").fetchone()[0] == 0


def test_full_purge_refuses_unconsumed_intake(store, cfg, raw):
    capture(cfg, raw, "one")
    with pytest.raises(ValueError, match="intake remains"):
        dispatch(parser().parse_args(["cleanup", "--purge-all", "--confirm"]), cfg, store)


def test_statistics_retention_stays_opt_in(store, cfg, raw):
    ready(store, cfg, raw)
    store.db.execute("UPDATE messages SET created='2000-01-01T00:00:00Z'")
    cleanup(store, cfg)
    assert store.db.execute("SELECT count(*) FROM observations").fetchone()[0] == 0


def test_delivery_query_uses_hash_index(store):
    plan = store.db.execute(
        "EXPLAIN QUERY PLAN SELECT DISTINCT source FROM deliveries WHERE hash=?", ("test",)
    ).fetchall()
    assert any("SEARCH" in row[3] and "deliveries_hash_source" in row[3] for row in plan)


def test_schema_v1_upgrade_preserves_data(cfg, raw):
    first = Store(cfg.data_dir)
    digest = first.ingest(raw, "one")
    first.db.execute("DROP TABLE observations")
    first.db.execute("DROP INDEX deliveries_hash_source")
    first.db.execute("PRAGMA user_version=1")
    first.close()
    second = Store(cfg.data_dir)
    try:
        assert second.message(digest)["raw"] == raw
        assert second.db.execute("PRAGMA user_version").fetchone()[0] == 2
    finally:
        second.close()
