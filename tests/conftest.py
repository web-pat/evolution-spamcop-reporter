import pytest

from spamreporter.config import Config, Source
from spamreporter.store import Store


@pytest.fixture
def raw():
    return (
        b"Received: from sender.example (sender.example [8.8.8.8]) by mx.example; "
        b"Wed, 11 Nov 2026 10:00:00 +0000\r\n"
        b"From: Synthetic <sender@example.org>\r\nTo: recipient@example.net\r\n"
        b"Message-ID: <synthetic@example.org>\r\nSubject: Synthetic test only\r\n"
        b"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nSynthetic body.\r\n"
    )


@pytest.fixture
def cfg(tmp_path):
    return Config(
        data_dir=tmp_path / "data",
        recipient="submit.TESTONLY@spamcop.net",
        identities={"default": "reporter@example.net"},
        sources={"one": Source("one", trusted_hosts={"mx.example": []}), "two": Source("two")},
    )


@pytest.fixture
def store(cfg):
    instance = Store(cfg.data_dir)
    yield instance
    instance.close()
