import io
import tempfile
import zipfile
from pathlib import Path

from archive_container_probe import (
    ZIP_CONTAINER_MAGICS,
    header_is_zip_container_magic,
    sniff_zip_container,
)
from transition_xray import _archive_entry_details


def _write_zip(path: Path, entries):
    fixed_date = (2026, 5, 31, 0, 0, 0)
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries:
            info = zipfile.ZipInfo(name, fixed_date)
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)


def test_header_is_zip_container_magic():
    assert header_is_zip_container_magic(b"PK\x03\x04")
    assert header_is_zip_container_magic(b"PK\x05\x06")
    assert not header_is_zip_container_magic(b"not-a-zip")


def test_sniff_zip_container_ignores_suffix():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for suffix in (".zip", ".whl", ".jar", ".docx", ".xlsx", ".bin", ".dat"):
            path = root / f"renamed{suffix}"
            _write_zip(path, (("normal.txt", b"ok"),))
            assert sniff_zip_container(path), suffix


def test_archive_entry_details_a1_magic_not_suffix():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for suffix in (".zip", ".whl", ".jar", ".docx", ".bin"):
            path = root / f"payload{suffix}"
            _write_zip(path, (("../../../../tmp/escaped", b"pwn"),))
            details = _archive_entry_details(path)
            assert details["archive_format"] == "zip", suffix
            assert details["archive_recognition_method"] == "zip_magic_v1", suffix
            assert details["archive_name_suffix"] == suffix, suffix
            assert "../../../../tmp/escaped" in details["archive_escape_entries"], suffix


def test_non_zip_suffix_name_without_magic_is_not_scanned():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "plain.zip"
        path.write_text("this is not a zip", encoding="utf-8")
        assert not sniff_zip_container(path)
        assert _archive_entry_details(path) == {}


def test_nested_archive_escape_is_recursed():
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("../../evil_nested", b"pwn")
    with tempfile.TemporaryDirectory() as tmp:
        outer = Path(tmp) / "outer.whl"
        _write_zip(outer, (("inner.zip", inner.getvalue()),))
        details = _archive_entry_details(outer)
        assert details["archive_nested_count"] >= 1
        assert "inner.zip!../../evil_nested" in details["archive_escape_entries"]


def test_zip_magics_tuple_is_stable():
    assert ZIP_CONTAINER_MAGICS[0] == b"PK\x03\x04"
