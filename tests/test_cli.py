import os
import subprocess
import sys
from pathlib import Path

import pytest

from spamreporter.cli import main
from spamreporter.config import load


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return tmp_path


def invoke(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["spamreporter", *args])
    return main()


def test_cli_offline_end_to_end(isolated, monkeypatch, capsys, raw):
    assert invoke(monkeypatch, "init") == 0
    path = isolated / "config/spamreporter/config.toml"
    text = path.read_text().replace('recipient = ""', 'recipient = "submit.TESTONLY@spamcop.net"')
    path.write_text(text)
    assert invoke(monkeypatch, "doctor") == 0
    sample = isolated / "sample.eml"
    sample.write_bytes(raw)
    capsys.readouterr()
    assert invoke(monkeypatch, "ingest", "--file", str(sample), "--source", "evolution") == 0
    digest = capsys.readouterr().out.strip()
    assert invoke(monkeypatch, "analyze") == 0
    assert invoke(monkeypatch, "review", digest) == 0
    assert invoke(monkeypatch, "queue", digest, "--source", "evolution") == 1
    assert invoke(monkeypatch, "queue", digest, "--source", "evolution", "--confirm-spam") == 0
    assert invoke(monkeypatch, "prepare", "--dry-run") == 0
    assert invoke(monkeypatch, "prepare") == 0
    assert invoke(monkeypatch, "send", digest, "--dry-run") == 0
    assert invoke(monkeypatch, "send", digest) == 0
    for format_name in ("html", "csv"):
        output = isolated / f"report.{format_name}"
        assert invoke(monkeypatch, "report", "--format", format_name, "--output", str(output)) == 0
        assert output.stat().st_mode & 0o777 == 0o600
    assert invoke(monkeypatch, "status", "--id", digest) == 0
    assert invoke(monkeypatch, "cleanup", "--dry-run") == 0
    assert invoke(monkeypatch, "cleanup", "--purge-all", "--confirm") == 0


def test_real_stdin_process_offline(isolated, raw):
    env = {**os.environ, "PYTHONPATH": str(Path("src").resolve())}
    command = [sys.executable, "-m", "spamreporter.cli"]
    subprocess.run([*command, "init"], env=env, check=True, capture_output=True)
    result = subprocess.run(
        [*command, "ingest", "--stdin", "--source", "evolution"],
        env=env,
        input=raw,
        capture_output=True,
        check=True,
    )
    assert len(result.stdout.strip()) == 64


def test_missing_config_and_private_permissions(isolated, monkeypatch):
    assert invoke(monkeypatch, "doctor") == 1
    assert invoke(monkeypatch, "init") == 0
    path = isolated / "config/spamreporter/config.toml"
    path.chmod(0o644)
    with pytest.raises(ValueError, match="chmod"):
        load(path)


def test_config_rejects_duplicate_sources(isolated, monkeypatch):
    assert invoke(monkeypatch, "init") == 0
    path = isolated / "config/spamreporter/config.toml"
    with path.open("a") as stream:
        stream.write('\n[[sources]]\nname="evolution"\n')
    with pytest.raises(ValueError, match="unique"):
        load(path)


@pytest.mark.parametrize("setting", ["allow_send", "allow_automatic", "auto_submit", "enabled"])
def test_quoted_permissions_fail_closed(isolated, monkeypatch, setting):
    assert invoke(monkeypatch, "init") == 0
    path = isolated / "config/spamreporter/config.toml"
    value = "true" if setting == "enabled" else "false"
    path.write_text(path.read_text().replace(f"{setting} = {value}", f'{setting} = "{value}"'))
    with pytest.raises(ValueError, match="booleans"):
        load(path)
