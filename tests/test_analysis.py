import json

import pytest

from spamreporter.analysis import ASNTable, analyze, origin, parse


@pytest.mark.parametrize("peer", ["8.8.8.8", "2606:4700:4700::1111"])
def test_direct_ipv4_ipv6(peer):
    result = origin([f"from unknown.example ([{peer}]) by mx.example; date"], {"mx.example": []})
    assert result["ip"] == peer
    assert result["confidence"] == "boundary-candidate"


def test_forwarding_stops_at_trust_boundary():
    headers = [
        "from forward.example ([1.1.1.1]) by mx.example; date",
        "from sender.example ([8.8.8.8]) by forward.example; date",
        "from innocent.example ([9.9.9.9]) by sender.example; forged",
    ]
    trust = {"mx.example": [], "forward.example": ["1.1.1.1/32"]}
    assert origin(headers, trust)["ip"] == "8.8.8.8"
    assert origin(headers, {"mx.example": []})["ip"] == "1.1.1.1"
    assert origin(headers, {"mx.example": [], "forward.example": ["1.0.0.0/24"]})["ip"] == "unknown"


@pytest.mark.parametrize(
    "headers",
    [
        [],
        ["malformed"],
        ["from sender ([10.0.0.1]) by mx.example; date"],
        ["from sender ([8.8.8.8] [9.9.9.9]) by mx.example; date"],
        [
            "from sender ([8.8.8.8]) by evil.example; date",
            "from sender ([9.9.9.9]) by mx.example; forged",
        ],
        [
            "from forward.example ([1.1.1.1]) by mx.example; date",
            "from sender ([8.8.8.8]) by different.example; date",
        ],
    ],
)
def test_unverifiable_is_unknown(headers):
    assert origin(headers, {"mx.example": [], "forward.example": ["1.1.1.1/32"]})["ip"] == "unknown"


def test_authentication_claims_not_verified(raw):
    metadata = parse(b"Authentication-Results: mx.example; spf=pass dkim=fail dmarc=pass\r\n" + raw)
    assert metadata["authentication_claims"]["dkim"] == ["fail"]
    assert not metadata["authentication_verified"]


def test_asn_longest_prefix(tmp_path):
    path = tmp_path / "asn.csv"
    path.write_text(
        "network,asn,operator\n8.0.0.0/8,AS64500,Example A\n"
        "8.8.8.0/24,AS64501,Example B\n2001:db8::/32,AS64502,Example V6\n"
    )
    table = ASNTable(str(path))
    assert table.lookup("8.8.8.8")["asn"] == "AS64501"
    assert table.lookup("2001:db8::1")["asn"] == "AS64502"
    assert table.lookup("1.1.1.1")["asn"] == "unknown"


def test_per_mailbox_trust(store, cfg, raw):
    digest = store.ingest(raw, "one")
    store.ingest(raw, "two")
    analyze(store, cfg)
    metadata = json.loads(store.message(digest)["metadata"])
    assert metadata["origins"]["one"]["ip"] == "8.8.8.8"
    assert metadata["origins"]["two"]["ip"] == "unknown"


def test_malformed_mime_requires_review(store, cfg):
    digest = store.ingest(b"Content-Type: multipart/mixed; boundary=absent\r\n\r\nbody", "one")
    analyze(store, cfg)
    assert store.message(digest)["state"] == "manual_review"


def test_late_delivery_adds_source_analysis_without_requeue(store, cfg, raw):
    digest = store.ingest(raw, "one")
    analyze(store, cfg)
    store.queue(digest, "one")
    store.ingest(raw, "two")
    assert analyze(store, cfg) == 1
    row = store.message(digest)
    assert row["state"] == "queued"
    assert json.loads(row["metadata"])["origins"]["two"]["ip"] == "unknown"
    assert analyze(store, cfg) == 0
