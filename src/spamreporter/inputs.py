"""Read-only adapters. Never interpret an IMAP cache as Maildir."""

import hashlib
import mailbox
import os
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

from .config import Source


def bounded_read(stream: BinaryIO, limit: int) -> bytes:
    data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Empty message or input size limit exceeded")
    return data


def read_file(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Input must be a regular file")
        raw = bounded_read(stream, limit)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Input changed during read; retry after delivery completes")
        return raw


def scan(
    source: Source, limit: int, on_error: Callable[[Exception], None] | None = None
) -> Iterator[tuple[str, bytes]]:
    def failed(error: Exception) -> None:
        if on_error is None:
            raise error
        on_error(error)

    root = Path(source.path).expanduser()
    if root.is_symlink():
        raise ValueError("Source root must not be a symlink")
    if source.kind == "mbox":
        # Only static exports. mailbox never locks/writes unless asked explicitly.
        if not root.is_file() or root.stat().st_size > limit * 100:
            raise ValueError("Missing or oversized mbox export")
        box = mailbox.mbox(root, create=False)
        try:
            for key in box.iterkeys():
                try:
                    with box.get_file(key, from_=False) as stream:
                        raw = bounded_read(stream, limit)
                except (OSError, ValueError) as exc:
                    failed(exc)
                    continue
                yield hashlib.sha256(f"{root.resolve()}:{key}".encode()).hexdigest(), raw
        finally:
            box.close()
        return
    if source.kind == "eml" and root.is_file():
        yield hashlib.sha256(str(root.resolve()).encode()).hexdigest(), read_file(root, limit)
        return
    if not root.is_dir():
        raise ValueError("Source directory does not exist")
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        dirs[:] = sorted(d for d in dirs if d != "tmp" and not (Path(directory) / d).is_symlink())
        folder = Path(directory)
        if source.kind == "maildir" and not (
            folder.name in {"cur", "new"}
            and (folder.parent / "tmp").is_dir()
            and (folder.parent / "cur").is_dir()
            and (folder.parent / "new").is_dir()
        ):
            continue
        for name in sorted(files):
            path = folder / name
            if path.is_symlink() or (source.kind == "eml" and path.suffix.lower() != ".eml"):
                continue
            try:
                raw = read_file(path, limit)
            except FileNotFoundError:  # A Maildir message may move from new to cur.
                continue
            except (OSError, ValueError) as exc:
                failed(exc)
                continue
            if source.kind == "maildir":
                key = str(folder.parent.resolve() / name.split(":2,", 1)[0])
            else:
                key = str(path.resolve())
            # Avoid persisting potentially personal filesystem paths.
            yield hashlib.sha256(key.encode()).hexdigest(), raw
