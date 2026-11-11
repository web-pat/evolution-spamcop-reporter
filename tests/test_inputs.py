import io
import mailbox

import pytest

from spamreporter.config import Source
from spamreporter.inputs import bounded_read, read_file, scan


def test_recursive_maildir_skips_tmp_and_symlinks(tmp_path, raw):
    folder = tmp_path / ".Junk"
    for name in ("cur", "new", "tmp"):
        (folder / name).mkdir(parents=True)
    path = folder / "new" / "uid"
    path.write_bytes(raw)
    (folder / "tmp" / "partial").write_bytes(b"partial")
    (folder / "cur" / "link").symlink_to(path)
    source = Source("one", "maildir", str(tmp_path))
    before = list(scan(source, 10000))
    assert len(before) == 1
    path.rename(folder / "cur" / "uid:2,S")
    assert list(scan(source, 10000)) == before


def test_eml_recursive_and_size_limit(tmp_path, raw):
    (tmp_path / "sample.eml").write_bytes(raw)
    (tmp_path / "ignored.txt").write_bytes(raw)
    assert len(list(scan(Source("one", "eml", str(tmp_path)), 10000))) == 1
    with pytest.raises(ValueError):
        read_file(tmp_path / "sample.eml", 10)
    with pytest.raises(ValueError):
        bounded_read(io.BytesIO(b""), 100)


def test_mbox_export(tmp_path, raw):
    path = tmp_path / "export.mbox"
    box = mailbox.mbox(path)
    box.add(raw)
    box.close()
    before = path.read_bytes()
    records = list(scan(Source("one", "mbox", str(path)), 10000))
    assert len(records) == 1
    assert b"Synthetic body." in records[0][1]
    assert path.read_bytes() == before


def test_symlink_rejected(tmp_path, raw):
    original = tmp_path / "original.eml"
    original.write_bytes(raw)
    link = tmp_path / "link.eml"
    link.symlink_to(original)
    with pytest.raises(OSError):
        read_file(link, 10000)
