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
        # Deliberately narrow grammar: never guess from arbitrary IPs elsewhere in the header.
        match = re.match(r"\s*from\s+([\w.-]+)\s+(.*?)\s+by\s+([\w.-]+)\b", header, re.I)
        if not match:
            return unknown
        sender, peer_text, receiver = match.groups()
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
            with Path(path).expanduser().open(newline="", encoding="utf-8") as stream:
                for row in csv.DictReader(stream):
                    network = ipaddress.ip_network(row["network"])
                    asn = row["asn"]
                    if not re.fullmatch(r"AS\d+", asn):
                        raise ValueError("ASN CSV expects AS<number>")
                    self.entries.append((network, asn, row["operator"]))
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
    defects = [type(defect).__name__ for part in message.walk() for defect in part.defects]
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
    rows = store.db.execute("SELECT hash FROM messages WHERE purged=0").fetchall()
    for item in rows:
        with store.transaction():
            row = store.message(item["hash"])
            if row["raw"] is None:
                continue
            try:
                fresh = row["state"] == "captured"
                metadata = parse(row["raw"]) if fresh else json.loads(row["metadata"])
                if "received" not in metadata:
                    continue
                origins = metadata.setdefault("origins", {})
                sources = store.db.execute(
                    "SELECT DISTINCT source FROM deliveries WHERE hash=?", (row["hash"],)
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
                store.metadata(row["hash"], metadata)
                if fresh:
                    state = "manual_review" if metadata["defects"] else "analyzed"
                    store.transition(
                        row["hash"],
                        state,
                        "MIME defects require manual inspection" if metadata["defects"] else "",
                    )
            except (ValueError, TypeError, IndexError, RecursionError):
                if row["state"] == "captured":
                    store.transition(row["hash"], "manual_review", "Header parsing failed")
            count += 1
    return count
