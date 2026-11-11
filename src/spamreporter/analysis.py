"""Conservative header observations, not authentication or spam classification."""

import csv
import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

from .config import Config
from .store import Store


def origin(received: list[str], trusted: dict[str, list[str]]) -> dict:
    unknown = {"ip": "unknown", "confidence": "unknown", "provenance": "unverified chain"}
    trusted = {host.lower().rstrip("."): nets for host, nets in trusted.items()}
    expected = None
    for index, header in enumerate(received):
        # Tokenize once: nested whitespace quantifiers permit catastrophic backtracking.
        # Long/ambiguous syntax is unknown, not a reason to hold up mail intake.
        if len(header) > 16_384:
            return unknown
        tokens = header.split()
        if len(tokens) < 5 or tokens[0].lower() != "from":
            return unknown
        depth, boundary = 0, None
        for position, token in enumerate(tokens[2:], 2):
            if token.lower() == "by" and depth == 0:
                boundary = position
                break
            depth += token.count("(") - token.count(")")
            if depth < 0:
                return unknown
        if boundary is None or boundary + 1 >= len(tokens):
            return unknown
        sender, receiver = tokens[1], tokens[boundary + 1].removesuffix(";")
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host) for host in (sender, receiver)):
            return unknown
        peer_text = " ".join(tokens[2:boundary])
        sender, receiver = sender.lower().rstrip("."), receiver.lower().rstrip(".")
        if receiver not in trusted or (index > 0 and receiver != expected):
            return unknown
        ips = set()
        for text in re.findall(r"\[(?:IPv6:)?([^\]]+)\]", peer_text, re.I):
            try:
                ips.add(ipaddress.ip_address(text))
            except ValueError:
                return unknown
        if len(ips) != 1:
            return unknown
        peer = ips.pop()
        if peer.is_multicast or peer.is_unspecified:
            return unknown
        networks = [ipaddress.ip_network(net) for net in trusted.get(sender, [])]
        if any(peer in net for net in networks):
            expected = sender
            continue
        if not peer.is_global:
            return unknown
        # A configured forwarder with an unexpected IP is not an origin assertion.
        if sender in trusted:
            return unknown
        return {
            "ip": str(peer),
            "confidence": "boundary-candidate",
            "provenance": f"Received[{index}] by configured trust anchor; origin unproven",
        }
    return unknown


class ASNTable:
    """Offline CSV: network,asn,operator. Longest prefix wins."""

    def __init__(self, path: str = ""):
        self.entries = []
        self.provenance = "not configured"
        if path:
            line = 1
            try:
                with Path(path).expanduser().open(newline="", encoding="utf-8") as stream:
                    reader = csv.DictReader(stream, strict=True)
                    if reader.fieldnames != ["network", "asn", "operator"]:
                        raise ValueError("Invalid columns")
                    for row in reader:
                        line = reader.line_num
                        if None in row or any(value is None for value in row.values()):
                            raise ValueError("Invalid row")
                        network = ipaddress.ip_network(row["network"])
                        asn = row["asn"]
                        if not re.fullmatch(r"AS[0-9]+", asn) or not row["operator"].strip():
                            raise ValueError("Invalid ASN/operator")
                        self.entries.append((network, asn, row["operator"]))
            except (ValueError, csv.Error) as exc:
                raise ValueError(
                    f"Invalid ASN CSV at line {line}; expected network,asn,operator "
                    "with a CIDR network, AS<number> and nonempty operator"
                ) from exc
            self.entries.sort(key=lambda item: item[0].prefixlen, reverse=True)
            self.provenance = "local administrator-supplied CSV (not independently verified)"

    def lookup(self, value: str) -> dict:
        result = {
            "asn": "unknown",
            "network": "unknown",
            "operator": "unknown",
            "asn_provenance": self.provenance,
        }
        if value == "unknown":
            return result
        ip = ipaddress.ip_address(value)
        for network, asn, operator in self.entries:
            if ip in network:
                return {
                    "asn": asn,
                    "network": str(network),
                    "operator": operator,
                    "asn_provenance": self.provenance,
                }
        return result


def parse(raw: bytes) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    defects = []
    for part in message.walk():
        defects.extend(type(defect).__name__ for defect in part.defects)
        for _, header in part.items():
            defects.extend(type(defect).__name__ for defect in getattr(header, "defects", ()))
    sender = parseaddr(str(message.get("From", "")))[1]
    auth = [str(item) for item in message.get_all("Authentication-Results", [])]
    received = [str(item) for item in message.get_all("Received", [])]
    received_date = "unknown"
    if received and ";" in received[0]:
        try:
            received_date = parsedate_to_datetime(received[0].rsplit(";", 1)[1]).isoformat()
        except (ValueError, TypeError, OverflowError):
            pass
    results = {}
    for name in ("spf", "dkim", "dmarc"):
        results[name] = re.findall(rf"\b{name}=([\w-]+)", " ".join(auth), re.I)
    return {
        "message_id": str(message.get("Message-ID", "")),
        "date_claim": str(message.get("Date", "")),
        "sender_domain": sender.rsplit("@", 1)[-1].lower() if "@" in sender else "unknown",
        "recipient_claim": str(
            message.get("Original-Recipient", "")
            or message.get("Delivered-To", "")
            or message.get("To", "")
        ),
        "received": received,
        "received_date_claim": received_date,
        "authentication_claims": results,
        "authentication_verified": False,
        "defects": defects,
    }


def analyze(store: Store, cfg: Config) -> int:
    table = ASNTable(cfg.asn_csv)
    count = 0
    rows = store.db.execute("SELECT hash,state,metadata FROM messages WHERE purged=0").fetchall()
    for item in rows:
        fresh = item["state"] == "captured"
        try:
            metadata = json.loads(item["metadata"])
            if fresh:
                raw = store.message(item["hash"])["raw"]
                if raw is None:
                    continue
                metadata = parse(raw)
            if "received" not in metadata:
                continue
            origins = metadata.setdefault("origins", {})
            sources = store.db.execute(
                "SELECT DISTINCT source FROM deliveries WHERE hash=?", (item["hash"],)
            ).fetchall()
            missing = [s["source"] for s in sources if s["source"] not in origins]
            if not fresh and not missing:
                continue
            for source in missing:
                configured = cfg.sources.get(source)
                candidate = origin(
                    metadata["received"], configured.trusted_hosts if configured else {}
                )
                candidate.update(table.lookup(candidate["ip"]))
                origins[source] = candidate
            detail = "MIME/header defects require manual inspection" if metadata["defects"] else ""
        except (ValueError, TypeError, IndexError, RecursionError):
            if not fresh:
                continue
            metadata, detail = {}, "Header parsing failed"
        # Parsing/ASN lookup happens outside the lock. An optimistic check prevents
        # overwriting concurrent analysis, retention, or a manual state change.
        with store.transaction():
            current = store.db.execute(
                "SELECT state,metadata,purged FROM messages WHERE hash=?", (item["hash"],)
            ).fetchone()
            if (
                current is None
                or current["purged"]
                or current["metadata"] != item["metadata"]
                or (fresh and current["state"] != "captured")
            ):
                continue
            store.metadata(item["hash"], metadata)
            if fresh:
                store.transition(item["hash"], "manual_review" if detail else "analyzed", detail)
            count += 1
    return count
