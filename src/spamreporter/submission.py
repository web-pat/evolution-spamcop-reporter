"""MIME construction preserving the attachment bytes without reserialization."""

import re
import uuid
from email import policy
from email.message import EmailMessage
from email.utils import formatdate

from .config import Config, address
from .store import Store

MAX_MESSAGES = 20
MAX_BYTES = 50_000


def wire_size(payload: bytes) -> int:
    """Budget for LF→CRLF transport normalization without modifying stored originals."""
    return len(payload) + payload.count(b"\n") - payload.count(b"\r\n")


def build(originals: list[bytes], sender: str, recipient: str) -> bytes:
    if not 1 <= len(originals) <= MAX_MESSAGES:
        raise ValueError("A submission must contain 1–20 original messages")
    sender, recipient = address(sender), address(recipient)
    # RFC 2046 prohibits base64/QP encoding a message/rfc822 entity. Preserve 8bit
    # bytes instead; binary/non-line-oriented input requires manual handling.
    for raw in originals:
        if not raw or b"\x00" in raw or re.search(rb"\r(?!\n)", raw):
            raise ValueError("Original is not a line-oriented RFC 5322 message")
        if any(len(line.rstrip(b"\r")) > 998 for line in raw.split(b"\n")):
            raise ValueError("Original exceeds RFC line limit; manual review required")
    boundary = "=_spamreporter_" + uuid.uuid4().hex
    while any(boundary.encode() in raw for raw in originals):
        boundary = "=_spamreporter_" + uuid.uuid4().hex
    headers = EmailMessage(policy=policy.SMTP)
    headers["From"] = sender
    headers["To"] = recipient
    headers["Subject"] = "Spam submission"
    headers["Date"] = formatdate(localtime=False, usegmt=True)
    headers["Message-ID"] = f"<{uuid.uuid4().hex}@{sender.rsplit('@', 1)[1]}>"
    headers["MIME-Version"] = "1.0"
    headers["Content-Transfer-Encoding"] = "8bit"
    headers["Content-Type"] = f'multipart/mixed; boundary="{boundary}"'
    result = headers.as_bytes().split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
    marker = b"--" + boundary.encode()
    result += marker + b"\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
    result += b"Please process the attached unsolicited bulk email.\r\n"
    for index, raw in enumerate(originals, 1):
        result += marker + b"\r\nContent-Type: message/rfc822\r\n"
        result += b"Content-Transfer-Encoding: 8bit\r\n"
        result += f'Content-Disposition: attachment; filename="spam-{index}.eml"\r\n\r\n'.encode()
        # The separator CRLF belongs to the MIME boundary, not to the original.
        result += raw + b"\r\n"
    result += marker + b"--\r\n"
    if wire_size(result) > MAX_BYTES:
        raise ValueError("Submission exceeds 50,000 bytes including MIME/CRLF overhead")
    return result


def prepare(store: Store, cfg: Config, limit: int = 20, dry_run: bool = False) -> list[str]:
    prepared = []
    rows = store.db.execute(
        "SELECT hash FROM messages WHERE state='queued' AND purged=0 ORDER BY created LIMIT ?",
        (limit,),
    ).fetchall()
    for item in rows:
        row = store.db.execute("SELECT * FROM messages WHERE hash=?", (item["hash"],)).fetchone()
        if row is None or row["state"] != "queued" or row["purged"]:
            continue
        error = ""
        try:
            sender, recipient = cfg.submission_addresses(row["approved_source"])
            if row["raw"] is None:
                raise ValueError("Original expired")
            payload = build([row["raw"]], sender, recipient)
        except ValueError as exc:
            error = str(exc)
        if dry_run:
            if not error:
                prepared.append(row["hash"])
            continue
        with store.transaction():
            current = store.db.execute(
                "SELECT state,purged,approved_source FROM messages WHERE hash=?", (row["hash"],)
            ).fetchone()
            if (
                current is None
                or current["state"] != "queued"
                or current["purged"]
                or current["approved_source"] != row["approved_source"]
            ):
                continue
            if error:
                store.transition(row["hash"], "manual_review", error)
                continue
            store.db.execute(
                "INSERT INTO submissions(hash,payload,sender,recipient) VALUES(?,?,?,?)",
                (row["hash"], payload, sender, recipient),
            )
            store.transition(row["hash"], "prepared")
            prepared.append(row["hash"])
    return prepared
