"""Command-line orchestration. Import never classifies or sends a message."""

import argparse
import hashlib
import importlib.resources
import json
import os
import shutil
import sqlite3
import sys
from pathlib import Path

from .analysis import analyze
from .config import Config, config_path, load, private_dir, private_write
from .inputs import bounded_read, read_file, scan
from .intake import capture, drain
from .maintenance import cleanup
from .reporting import render_csv, render_html, terminal
from .store import Store
from .submission import prepare
from .transports import materialize, record_evidence, send


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="Local-first spam review and SpamCop submission")
    cli.add_argument(
        "--config", type=Path, default=config_path(), help="Private TOML configuration"
    )
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create private sample configuration and local database")
    commands.add_parser(
        "doctor", help="Validate configuration, permissions, sources and selected mode"
    )
    ingest = commands.add_parser("ingest", help="Capture bytes locally; never analyze or send")
    input_group = ingest.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Durably spool binary RFC 5322 bytes; stdout stays silent",
    )
    input_group.add_argument("--file", type=Path, help="Read a single EML file")
    ingest.add_argument("--source", required=True, help="Enabled configured source name")
    ingest.add_argument("--delivery-id", default="", help="Optional stable delivery UID for stdin")
    scanner = commands.add_parser("scan", help="Read enabled local sources without modifying them")
    scanner.add_argument("--source", help="Scan only this source")
    scanner.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum new deliveries per run (default 1000); known files are skipped",
    )
    commands.add_parser(
        "analyze", help="Parse captured messages and perform offline IP/ASN analysis"
    )
    queue = commands.add_parser(
        "queue", help="List candidates or explicitly queue reviewed fingerprints"
    )
    queue.add_argument("ids", nargs="*", help="Full SHA-256 fingerprints")
    queue.add_argument("--source", help="Source whose identity and permission apply")
    queue.add_argument(
        "--confirm-spam", action="store_true", help="Attest unsolicited bulk email review"
    )
    review = commands.add_parser("review", help="Export one exact original for local inspection")
    review.add_argument("id", help="Full SHA-256 fingerprint")
    prep = commands.add_parser(
        "prepare", help="Build immutable MIME for explicitly queued messages"
    )
    prep.add_argument("--limit", type=int, default=20, help="Maximum submissions (1–20)")
    prep.add_argument("--dry-run", action="store_true", help="Validate without changing state")
    sender = commands.add_parser(
        "send", help="Export EML, open a draft, or hand off to local sendmail"
    )
    sender.add_argument(
        "ids", nargs="*", help="Full fingerprints; --automatic selects prepared items"
    )
    sender.add_argument("--backend", choices=["eml", "evolution", "sendmail"])
    sender.add_argument(
        "--confirm", action="store_true", help="Explicitly authorize transport/editor"
    )
    sender.add_argument(
        "--automatic", action="store_true", help="Use global and per-source opt-ins"
    )
    sender.add_argument(
        "--retry", action="store_true", help="Retry only a transport that failed to start"
    )
    sender.add_argument(
        "--dry-run", action="store_true", help="No files, processes or state changes"
    )
    status = commands.add_parser(
        "status", help="Show state counts or record human-reviewed evidence"
    )
    status.add_argument("--id", help="Show state/event history for this fingerprint")
    status.add_argument(
        "--record", choices=["handed_off", "response_received", "completed", "cancelled"]
    )
    status.add_argument(
        "--evidence", type=Path, help="Local proof: reply EML, MTA receipt or report record"
    )
    status.add_argument(
        "--attest", action="store_true", help="Attest that you verified this evidence"
    )
    report = commands.add_parser(
        "report", help="Generate local observations; addresses are omitted"
    )
    report.add_argument("--format", choices=["terminal", "html", "csv"], default="terminal")
    report.add_argument("--output", type=Path, help="New private report file (never overwrites)")
    clean = commands.add_parser(
        "cleanup", help="Expire private data, retaining deduplication tombstones"
    )
    clean.add_argument("--dry-run", action="store_true")
    clean.add_argument(
        "--purge-all", action="store_true", help="Erase all DB records and owned exports"
    )
    clean.add_argument("--confirm", action="store_true", help="Required for irreversible purge-all")
    return cli


def doctor(cfg: Config, path: Path, store: Store) -> int:
    checks = [
        ("private configuration", not bool(path.stat().st_mode & 0o077)),
        ("SQLite integrity", store.db.execute("PRAGMA quick_check").fetchone()[0] == "ok"),
    ]
    for source in cfg.sources.values():
        if source.enabled:
            checks.append(
                (
                    f"source {source.name}",
                    source.kind == "stdin" or Path(source.path).expanduser().exists(),
                )
            )
            try:
                cfg.submission_addresses(source.name)
                valid = True
            except ValueError:
                valid = False
            checks.append((f"submission identity {source.name}", valid))
    for item in cfg.data_dir.rglob("*"):
        if item.is_symlink() or item.stat().st_mode & 0o077:
            checks.append(("private data permissions", False))
            break
    if cfg.backend == "evolution":
        checks.append(("Evolution executable", shutil.which("evolution") is not None))
        checks.append(
            (
                "desktop session",
                bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
            )
        )
    if cfg.backend == "sendmail":
        checks.append(("sendmail executable", shutil.which(cfg.sendmail[0]) is not None))
        checks.append(("sendmail explicitly enabled", cfg.allow_send))
    if cfg.asn_csv:
        from .analysis import ASNTable

        ASNTable(cfg.asn_csv)
        checks.append(("offline ASN table", True))
    for name, ok in checks:
        print(f"{'OK' if ok else 'FAIL'}  {name}")
    print("Evolution attachment acceptance and MTA delivery require local integration checks.")
    return 0 if all(ok for _, ok in checks) else 1


def run(args: argparse.Namespace) -> int:
    if args.command == "init":
        private_dir(args.config.parent)
        template = importlib.resources.files("spamreporter").joinpath("defaults.toml").read_bytes()
        private_write(args.config, template)
        cfg = load(args.config)
        Store(cfg.data_dir).close()
        print("Initialized. Edit the private config and run doctor; sending is disabled.")
        return 0
    cfg = load(args.config)
    if args.command == "ingest" and args.stdin:
        # Camel interprets stdout as a replacement message. Never print here, and
        # never wait for a SQLite writer while Evolution is feeding the pipe.
        capture(
            cfg, bounded_read(sys.stdin.buffer, cfg.max_input_bytes), args.source, args.delivery_id
        )
        return 0
    store = Store(cfg.data_dir)
    try:
        if not getattr(args, "dry_run", False):
            _, failures = drain(store, cfg)
            if failures:
                print(f"Intake: {failures} unreadable records retained for review", file=sys.stderr)
        return dispatch(args, cfg, store)
    finally:
        store.close()


def dispatch(args: argparse.Namespace, cfg: Config, store: Store) -> int:
    command = args.command
    if command == "doctor":
        return doctor(cfg, args.config, store)
    if command == "ingest":
        if args.stdin:
            capture(
                cfg,
                bounded_read(sys.stdin.buffer, cfg.max_input_bytes),
                args.source,
                args.delivery_id,
            )
            return 0
        cfg.source(args.source)
        raw = (
            bounded_read(sys.stdin.buffer, cfg.max_input_bytes)
            if args.stdin
            else read_file(args.file, cfg.max_input_bytes)
        )
        key = args.delivery_id or (str(args.file.resolve()) if args.file else "")
        key = hashlib.sha256(key.encode()).hexdigest() if key else ""
        print(store.ingest(raw, args.source, key, cfg.max_input_bytes))
    elif command == "scan":
        if args.limit < 1:
            raise ValueError("Scan limit must be positive")
        sources = [cfg.source(args.source)] if args.source else list(cfg.sources.values())
        count, failures = 0, 0
        for source in sources:
            if not source.enabled or source.kind == "stdin":
                continue

            def input_error(error: Exception, name: str = source.name) -> None:
                nonlocal failures
                failures += 1
                print(
                    f"Source {name}: skipped unreadable, changed or oversized input "
                    f"({type(error).__name__})",
                    file=sys.stderr,
                )

            try:
                for key, raw in scan(source, cfg.max_input_bytes, on_error=input_error):
                    if count >= args.limit:
                        break
                    digest = hashlib.sha256(raw).hexdigest()
                    known = store.db.execute(
                        "SELECT 1 FROM deliveries WHERE hash=? AND source=? AND delivery_key=?",
                        (digest, source.name, key),
                    ).fetchone()
                    if not known:
                        store.ingest(raw, source.name, key, cfg.max_input_bytes)
                        count += 1
            except (OSError, ValueError):
                print(
                    f"Source {source.name}: scan failed; inspect source and input sizes",
                    file=sys.stderr,
                )
                failures += 1
        print(f"Captured {count} new deliveries; {failures} source errors")
        # A distinct partial-failure status lets the user service continue maintenance.
        return 2 if failures else 0
    elif command == "analyze":
        print(f"Analyzed {analyze(store, cfg)} messages")
    elif command == "queue":
        if args.ids:
            if not args.confirm_spam or not args.source:
                raise ValueError(
                    "Queueing requires --source and --confirm-spam after reviewing originals"
                )
            cfg.source(args.source)
            for digest in args.ids:
                store.queue(digest, args.source)
            print(f"Queued {len(args.ids)} reviewed messages")
        else:
            for row in store.db.execute(
                "SELECT hash,state FROM messages WHERE purged=0 ORDER BY created"
            ):
                print(row["hash"], row["state"])
    elif command == "review":
        with store.transaction():
            row = store.message(args.id)
            if row["raw"] is None:
                raise ValueError("Original expired")
            directory = cfg.data_dir / "review"
            private_dir(directory)
            materialize(directory / f"{row['hash']}.eml", row["raw"])
        print(f"Original exported to private review/{row['hash']}.eml")
    elif command == "prepare":
        if not 1 <= args.limit <= 20:
            raise ValueError("Prepare limit must be 1–20")
        for digest in prepare(store, cfg, args.limit, args.dry_run):
            print(digest, "validated" if args.dry_run else "prepared")
    elif command == "send":
        ids = args.ids
        if not ids and args.automatic:
            ids = [
                r[0]
                for r in store.db.execute(
                    "SELECT m.hash,m.approved_source FROM messages m "
                    "JOIN submissions s ON s.hash=m.hash WHERE m.state='prepared' "
                    "AND m.purged=0 AND s.payload IS NOT NULL ORDER BY m.created"
                )
                if r[1] in cfg.sources
                and cfg.sources[r[1]].enabled
                and cfg.sources[r[1]].auto_submit
            ][:20]
        if len(ids) > 20 or (not ids and not args.automatic):
            raise ValueError("Supply 1–20 fingerprints, or --automatic for reviewed prepared work")
        failures = 0
        for digest in ids:
            try:
                outcome = send(
                    store,
                    cfg,
                    digest,
                    backend=args.backend,
                    confirm=args.confirm,
                    automatic=args.automatic,
                    retry=args.retry,
                    dry_run=args.dry_run,
                )
            except ValueError as exc:
                if not args.automatic:
                    raise
                print(f"{digest}: {exc}", file=sys.stderr)
                failures += 1
                continue
            print(digest, outcome)
            failures += outcome in {"error", "manual_review"}
        return bool(failures)
    elif command == "status":
        if args.record:
            if not (args.id and args.evidence and args.attest):
                raise ValueError("Recording requires --id --evidence and --attest")
            record_evidence(
                store, args.id, args.record, read_file(args.evidence, cfg.max_input_bytes)
            )
        if args.id:
            row = store.message(args.id)
            print(row["hash"], row["state"], row["error"] or "")
            for event in store.db.execute(
                "SELECT created,state,detail FROM events WHERE hash=?", (args.id,)
            ):
                print(*event)
        else:
            print(
                json.dumps(
                    dict(store.db.execute("SELECT state,count(*) FROM messages GROUP BY state")),
                    indent=2,
                )
            )
    elif command == "report":
        result = {"terminal": terminal, "html": render_html, "csv": render_csv}[args.format](
            store, cfg
        )
        if args.output:
            private_write(args.output, result.encode("utf-8"))
        else:
            print(result)
    elif command == "cleanup":
        if args.purge_all:
            if not args.confirm:
                raise ValueError(
                    "--purge-all requires --confirm; deduplication history will be lost"
                )
            if args.dry_run:
                print("Would purge all records and application-owned exports")
                return 0
            intake = cfg.data_dir / "intake"
            if intake.exists() and any(intake.iterdir()):
                raise ValueError(
                    "Pending or incomplete intake remains; stop the filter and "
                    "inspect the private intake directory before purging"
                )
            with store.transaction():
                if store.db.execute(
                    "SELECT 1 FROM messages WHERE state IN ('handing_off','draft_opened')"
                ).fetchone():
                    raise ValueError("Resolve active transport/editor outcomes before purging")
                for folder in ("outbox", "draft-attachments", "review"):
                    directory = cfg.data_dir / folder
                    if directory.exists():
                        private_dir(directory)
                        for row in store.db.execute("SELECT hash FROM messages"):
                            (directory / f"{row['hash']}.eml").unlink(missing_ok=True)
                for table in (
                    "observations",
                    "evidence",
                    "events",
                    "submissions",
                    "deliveries",
                    "messages",
                ):
                    store.db.execute(f"DELETE FROM {table}")
            store.db.execute("VACUUM")
            store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            print("Purged. Existing source messages will be captured anew on the next scan.")
        else:
            print(f"Expired {cleanup(store, cfg, args.dry_run)} messages; fingerprints retained")
    return 0


def main() -> int:
    os.umask(0o077)
    try:
        return run(parser().parse_args())
    except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
        # OS/SQL errors may embed paths, addresses or payloads. Do not echo them.
        detail = str(exc) if type(exc) is ValueError else type(exc).__name__
        print(f"spamreporter: {detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
