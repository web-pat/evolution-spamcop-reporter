"""External transport boundary: claim first, never retry uncertain outcomes."""

import hashlib
import subprocess
from pathlib import Path
from urllib.parse import quote, urlencode

from .config import Config, private_dir, private_write
from .store import Store
from .submission import MAX_BYTES, wire_size


def launch_evolution(command: list[str]) -> int | None:
    """A first invocation can own the entire GUI lifetime. Never terminate it."""
    child = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        return child.wait(timeout=1)
    except subprocess.TimeoutExpired:
        # Still alive is normal for a new Evolution instance, not a failed send.
        # The short-lived CLI exits without killing the independent desktop process.
        return None


def materialize(path: Path, raw: bytes) -> None:
    if path.exists():
        if path.is_symlink() or path.stat().st_mode & 0o077 or path.read_bytes() != raw:
            raise ValueError("Export exists with unsafe permissions or different contents")
    else:
        private_write(path, raw)


def send(
    store: Store,
    cfg: Config,
    digest: str,
    *,
    backend: str | None = None,
    confirm: bool = False,
    automatic: bool = False,
    retry: bool = False,
    dry_run: bool = False,
) -> str:
    backend = backend or cfg.backend
    if backend not in {"eml", "evolution", "sendmail"}:
        raise ValueError("Unknown transport")
    with store.transaction():
        message = store.message(digest)
        submission = store.db.execute(
            "SELECT * FROM submissions WHERE hash=?", (digest,)
        ).fetchone()
        allowed = {"prepared"} | ({"error"} if retry else set())
        if (
            message["purged"]
            or message["state"] not in allowed
            or not submission
            or submission["payload"] is None
        ):
            raise ValueError("Submission not ready; ambiguous or handed-off work is never retried")
        if wire_size(submission["payload"]) > MAX_BYTES:
            raise ValueError("Submission size limit exceeded")
        source = cfg.source(message["approved_source"])
        if backend == "sendmail":
            if not cfg.allow_send or not (confirm or automatic):
                raise ValueError("Sendmail requires allow_send and --confirm or --automatic")
            if automatic and not (cfg.allow_automatic and source.auto_submit):
                raise ValueError("Automatic handoff requires global and source opt-in")
        if backend == "evolution" and (not confirm or automatic):
            raise ValueError("Opening Evolution requires --confirm and interactive review")
        if backend != "eml":
            attempts = store.db.execute(
                "SELECT count(*) FROM events WHERE state='handing_off' "
                "AND julianday(created)>julianday('now','-1 day')"
            ).fetchone()[0]
            if attempts >= cfg.daily_limit:
                raise ValueError("Rolling 24-hour attempt limit reached")
        if dry_run:
            return "dry-run: validated; no export, editor or transport invoked"
        if backend == "eml":
            # Serialize exports with retention so an expired BLOB is never recreated.
            directory = cfg.data_dir / "outbox"
            private_dir(directory)
            materialize(directory / f"{digest}.eml", submission["payload"])
            store.db.execute("UPDATE submissions SET backend='eml' WHERE hash=?", (digest,))
            if message["state"] == "error":
                store.transition(
                    digest, "prepared", "Offline fallback after failed transport start"
                )
            return "prepared: EML exported (not sent)"
        if backend != "eml":
            store.transition(digest, "handing_off", backend)
            store.db.execute(
                "UPDATE submissions SET attempts=attempts+1,backend=? WHERE hash=?",
                (backend, digest),
            )
    # No external processes run while holding the database write lock.
    try:
        if backend == "evolution":
            directory = cfg.data_dir / "draft-attachments"
            private_dir(directory)
            path = directory / f"{digest}.eml"
            materialize(path, message["raw"])
            uri = (
                "mailto:"
                + quote(submission["recipient"], safe="@")
                + "?"
                + urlencode(
                    {"subject": "Spam submission", "attach": str(path.resolve())}, quote_via=quote
                )
            )
            returncode = launch_evolution(["evolution", uri])
            detail = "Evolution launch requested; verify the composer and attachment"
        else:
            command = [*cfg.sendmail, "--", submission["recipient"]]
            result = subprocess.run(
                command,
                input=submission["payload"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
            )
            returncode, detail = result.returncode, backend
        state = "handed_off" if backend == "sendmail" else "draft_opened"
        if returncode:
            state = "manual_review"
            detail = "Transport returned nonzero; outcome uncertain"
    except (FileNotFoundError, PermissionError):
        state, detail = "error", "Transport could not be started; safe to retry"
    except OSError:
        state, detail = "manual_review", "Transport I/O failed; outcome uncertain"
    except subprocess.TimeoutExpired:
        state, detail = "manual_review", "Transport timed out; outcome uncertain"
    except ValueError:
        state, detail = "manual_review", "Private export failed; inspect before continuing"
    with store.transaction():
        if store.message(digest)["state"] == "handing_off":
            store.transition(digest, state, detail)
        else:
            state = store.message(digest)["state"]
    return state


def record_evidence(store: Store, digest: str, state: str, evidence: bytes) -> None:
    """Human-attested evidence, not automated verification of an email's claims."""
    predecessors = {
        "handed_off": {"prepared", "draft_opened", "handing_off", "manual_review"},
        "response_received": {"handed_off"},
        "completed": {"response_received"},
        "cancelled": {"prepared", "draft_opened", "handing_off", "manual_review", "error"},
    }
    if state not in predecessors or not evidence:
        raise ValueError("Invalid evidence state or empty evidence")
    with store.transaction():
        row = store.message(digest)
        if row["state"] not in predecessors[state]:
            raise ValueError("Evidence does not follow the submission lifecycle")
        submission = store.db.execute(
            "SELECT backend FROM submissions WHERE hash=?", (digest,)
        ).fetchone()
        if not submission:
            raise ValueError("No submission exists")
        if state == "handed_off" and row["state"] == "prepared" and submission["backend"] != "eml":
            raise ValueError("Record prepared handoff only after exporting the EML")
        store.db.execute(
            "INSERT INTO evidence(hash,digest,raw,kind) VALUES(?,?,?,?)",
            (digest, hashlib.sha256(evidence).hexdigest(), evidence, state),
        )
        store.transition(digest, state, "User-attested local evidence; not machine-authenticated")
