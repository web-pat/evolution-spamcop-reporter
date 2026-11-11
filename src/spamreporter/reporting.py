"""Privacy-conscious local observations in terminal, CSV and standalone HTML."""

import csv
import hashlib
import html
import io
import json
from collections import Counter, defaultdict

from .config import Config
from .store import Store

NOTICE = (
    "Observations of configured local mailboxes only, not global spam statistics. "
    "IP values are trust-boundary candidates, not proven origins. "
    "Dates count local capture time (UTC), not untrusted Date headers. "
    "Domains are pseudonymized; sender domains and authentication results are claims."
)


def pseudonym(value: str) -> str:
    return "domain-" + hashlib.sha256(value.encode()).hexdigest()[:12] if value else "unknown"


def rows(store: Store, cfg: Config) -> list[dict]:
    output = []
    for row in store.db.execute(
        "SELECT m.hash,m.state,m.metadata,d.source,d.created FROM messages m "
        "JOIN deliveries d ON m.hash=d.hash WHERE m.purged=0 ORDER BY d.created,d.id"
    ):
        metadata = json.loads(row["metadata"])
        candidate = metadata.get("origins", {}).get(row["source"], {})
        source = cfg.sources.get(row["source"])
        output.append(
            {
                "fingerprint": row["hash"],
                "captured_utc": row["created"],
                "source": row["source"],
                "mailbox_domain": pseudonym(source.domain if source else ""),
                "sender_domain_claim": pseudonym(metadata.get("sender_domain", "")),
                "state": row["state"],
                **{
                    key: candidate.get(key, "unknown")
                    for key in (
                        "ip",
                        "confidence",
                        "provenance",
                        "asn",
                        "network",
                        "operator",
                        "asn_provenance",
                    )
                },
            }
        )
    return output


def tables(store: Store, cfg: Config) -> dict[str, list[list[str]]]:
    observations = rows(store, cfg)
    sections = {}
    for title, key in (
        ("Deliveries per day (UTC)", "day"),
        ("Deliveries per month (UTC)", "month"),
        ("Deliveries by source", "source"),
        ("Deliveries by mailbox domain", "mailbox_domain"),
        ("Sender domain claims", "sender_domain_claim"),
        ("Network recurrence (deliveries)", "network"),
        ("Network operators (deliveries)", "operator"),
    ):
        counts = Counter(
            row["captured_utc"][: 10 if key == "day" else 7]
            if key in {"day", "month"}
            else row[key]
            for row in observations
        )
        sections[title] = [[key, "count"], *[[str(k), str(v)] for k, v in counts.most_common()]]
    groups = defaultdict(list)
    for row in observations:
        groups[row["ip"]].append(row)
    sections["IP observations"] = [["IP", "deliveries", "first UTC", "last UTC", "confidence"]]
    for ip, group in sorted(groups.items(), key=lambda item: -len(item[1])):
        sections["IP observations"].append(
            [
                ip,
                str(len(group)),
                min(row["captured_utc"] for row in group),
                max(row["captured_utc"] for row in group),
                group[0]["confidence"],
            ]
        )
    asns = defaultdict(list)
    for row in observations:
        asns[row["asn"]].append(row)
    sections["ASN observations"] = [["ASN", "deliveries", "distinct candidate IPs", "operator"]]
    for asn, group in sorted(asns.items(), key=lambda item: -len(item[1])):
        sections["ASN observations"].append(
            [
                asn,
                str(len(group)),
                str(len({r["ip"] for r in group if r["ip"] != "unknown"})),
                group[0]["operator"],
            ]
        )
    sections["Unique message states (including retention tombstones)"] = [
        ["state", "count"],
        *[
            [row[0], str(row[1])]
            for row in store.db.execute(
                "SELECT state,count(*) FROM messages GROUP BY state ORDER BY state"
            )
        ],
    ]
    sections["Submission totals (unique messages)"] = [["metric", "count"]]
    for label, condition in (
        ("prepared at least once", "1=1"),
        (
            "handed to transport (not delivery proof)",
            "m.state IN ('handed_off','response_received','completed')",
        ),
        ("completed with user-attested evidence", "m.state='completed'"),
        ("not completed", "m.state!='completed'"),
        ("errors / uncertain outcomes", "m.state IN ('error','manual_review','handing_off')"),
    ):
        count = store.db.execute(
            f"SELECT count(*) FROM submissions s JOIN messages m ON s.hash=m.hash WHERE {condition}"
        ).fetchone()[0]
        sections["Submission totals (unique messages)"].append([label, str(count)])
    sections["Attribution provenance"] = [["source", "confidence", "provenance", "ASN provenance"]]
    unique = {
        (r["source"], r["confidence"], r["provenance"], r["asn_provenance"]) for r in observations
    }
    sections["Attribution provenance"].extend([list(item) for item in sorted(unique)])
    return sections


def safe_cell(value: str) -> str:
    # Prevent spreadsheet formula execution when someone opens the CSV in a GUI.
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value


def render_csv(store: Store, cfg: Config) -> str:
    records = rows(store, cfg)
    output = io.StringIO(newline="")
    fields = [
        "fingerprint",
        "captured_utc",
        "source",
        "mailbox_domain",
        "sender_domain_claim",
        "state",
        "ip",
        "confidence",
        "provenance",
        "asn",
        "network",
        "operator",
        "asn_provenance",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in records:
        writer.writerow({key: safe_cell(str(value)) for key, value in row.items()})
    return output.getvalue()


def render_html(store: Store, cfg: Config) -> str:
    output = [
        '<!doctype html><html lang="en"><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">',
        "<title>Local spam observations</title><h1>Local spam observations</h1>",
        f"<p>{html.escape(NOTICE)}</p>",
    ]
    for name, table in tables(store, cfg).items():
        output.append(f"<h2>{html.escape(name)}</h2><table>")
        for index, row in enumerate(table):
            tag = "th" if index == 0 else "td"
            output.append(
                "<tr>" + "".join(f"<{tag}>{html.escape(cell)}</{tag}>" for cell in row) + "</tr>"
            )
        output.append("</table>")
    return "\n".join(output) + "\n</html>\n"


def terminal(store: Store, cfg: Config) -> str:
    output = [NOTICE]
    for name, table in tables(store, cfg).items():
        # Escape hostile control sequences before printing any untrusted metadata.
        safe = [
            ["".join(c if c.isprintable() else "?" for c in cell) for cell in row] for row in table
        ]
        widths = [max(len(row[i]) for row in safe) for i in range(len(safe[0]))]
        output.extend(["", name])
        output.extend(
            "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in safe
        )
    return "\n".join(output)
