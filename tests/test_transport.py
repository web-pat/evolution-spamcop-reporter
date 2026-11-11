import subprocess
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from spamreporter.analysis import analyze
from spamreporter.store import Store
from spamreporter.submission import prepare
from spamreporter.transports import record_evidence, send


@pytest.fixture
def ready(store, cfg, raw):
    digest = store.ingest(raw, "one")
    analyze(store, cfg)
    store.queue(digest, "one")
    prepare(store, cfg)
    return digest


def test_default_export_is_not_sent(store, cfg, ready, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Process called"))
    send(store, cfg, ready, dry_run=True)
    assert not (cfg.data_dir / "outbox").exists()
    send(store, cfg, ready)
    assert (cfg.data_dir / "outbox" / f"{ready}.eml").exists()
    assert store.message(ready)["state"] == "prepared"


def test_send_requires_opt_in(store, cfg, ready, monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Process called"))
    with pytest.raises(ValueError):
        send(store, cfg, ready, backend="sendmail", confirm=True)
    cfg.allow_send = True
    with pytest.raises(ValueError):
        send(store, cfg, ready, backend="sendmail", automatic=True)
    send(store, cfg, ready, backend="sendmail", confirm=True, dry_run=True)
    assert store.message(ready)["state"] == "prepared"


def test_handoff_restart_no_duplicate(store, cfg, ready, monkeypatch):
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs["input"]))
        assert store.message(ready)["state"] == "handing_off"
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    cfg.allow_send = True
    assert send(store, cfg, ready, backend="sendmail", confirm=True) == "handed_off"
    other = Store(cfg.data_dir)
    try:
        with pytest.raises(ValueError):
            send(other, cfg, ready, backend="sendmail", confirm=True, retry=True)
    finally:
        other.close()
    assert len(calls) == 1
    assert calls[0][0][-2:] == ["--", cfg.recipient]


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "crash"])
def test_ambiguous_failure_never_retried(store, cfg, ready, monkeypatch, failure):
    def fake_run(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("redacted", 60)
        if failure == "crash":
            raise KeyboardInterrupt()
        return SimpleNamespace(returncode=75)

    monkeypatch.setattr(subprocess, "run", fake_run)
    cfg.allow_send = True
    if failure == "crash":
        with pytest.raises(KeyboardInterrupt):
            send(store, cfg, ready, backend="sendmail", confirm=True)
        assert store.message(ready)["state"] == "handing_off"
    else:
        assert send(store, cfg, ready, backend="sendmail", confirm=True) == "manual_review"
    with pytest.raises(ValueError):
        send(store, cfg, ready, backend="sendmail", confirm=True, retry=True)


def test_only_spawn_failure_retryable(store, cfg, ready, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(subprocess, "run", missing)
    cfg.allow_send = True
    assert send(store, cfg, ready, backend="sendmail", confirm=True) == "error"
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    assert send(store, cfg, ready, backend="sendmail", confirm=True, retry=True) == "handed_off"


def test_concurrent_handoff_claim(store, cfg, ready, monkeypatch):
    cfg.allow_send = True
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(1)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    def attempt(_):
        connection = Store(cfg.data_dir)
        try:
            return send(connection, cfg, ready, backend="sendmail", confirm=True)
        except ValueError:
            return "blocked"
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert results.count("handed_off") == 1
    assert len(calls) == 1


def test_evolution_attaches_original_not_wrapper(store, cfg, ready, raw, monkeypatch):
    def fake_run(command, **kwargs):
        query = parse_qs(urlsplit(command[1]).query)
        from pathlib import Path

        assert Path(query["attach"][0]).read_bytes() == raw
        assert cfg.recipient in command[1]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert send(store, cfg, ready, backend="evolution", confirm=True) == "draft_opened"
    with pytest.raises(ValueError):
        send(store, cfg, ready, backend="sendmail", confirm=True)


def test_evidence_lifecycle(store, cfg, ready, monkeypatch):
    with pytest.raises(ValueError):
        record_evidence(store, ready, "completed", b"synthetic evidence")
    cfg.allow_send = True
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0))
    send(store, cfg, ready, backend="sendmail", confirm=True)
    record_evidence(store, ready, "response_received", b"synthetic parser response")
    record_evidence(store, ready, "completed", b"synthetic verified completion record")
    assert store.message(ready)["state"] == "completed"


def test_daily_attempt_limit(store, cfg, ready, monkeypatch):
    cfg.allow_send = True
    cfg.daily_limit = 1
    with store.transaction():
        store.transition(ready, "handing_off", "simulated previous attempt")
        store.transition(ready, "error", "Transport failed to start")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("Process called"))
    with pytest.raises(ValueError, match="24-hour"):
        send(store, cfg, ready, backend="sendmail", confirm=True, retry=True)


def test_real_local_capture_transport(store, cfg, ready, tmp_path):
    """Execute an isolated local stand-in: writes bytes only, never sends mail."""
    import sys

    output = tmp_path / "captured.mime"
    cfg.allow_send = True
    cfg.sendmail = [
        sys.executable,
        "-c",
        "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())",
        str(output),
    ]
    assert send(store, cfg, ready, backend="sendmail", confirm=True) == "handed_off"
    expected = store.db.execute(
        "SELECT payload FROM submissions WHERE hash=?", (ready,)
    ).fetchone()[0]
    assert output.read_bytes() == expected


def test_transport_io_failure_is_uncertain(store, cfg, ready, monkeypatch):
    def broken(*args, **kwargs):
        raise OSError("synthetic I/O failure")

    monkeypatch.setattr(subprocess, "run", broken)
    cfg.allow_send = True
    assert send(store, cfg, ready, backend="sendmail", confirm=True) == "manual_review"
