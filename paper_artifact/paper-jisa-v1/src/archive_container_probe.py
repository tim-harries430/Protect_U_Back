from __future__ import annotations

from pathlib import Path

# ZIP local-file-header / central-directory / end-of-central-directory magic.
# Office docs (.docx/.xlsx/.pptx), wheels (.whl), jars (.jar), eggs, apks, and
# skill packages are ALL ZIP containers. A plain .zip can be renamed to any
# suffix; recognition must anchor on these unforgeable header bytes, never on the
# producer-chosen extension. (Red-team A1: trust physical bytes, not the name.)
ZIP_CONTAINER_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

# Informational only -- NEVER used as a scan gate. Documented aliases for operators.
ZIP_CONTAINER_SUFFIX_HINTS = frozenset(
    {
        ".zip",
        ".skillpkg",
        ".whl",
        ".jar",
        ".docx",
        ".xlsx",
        ".pptx",
        ".apk",
        ".epub",
        ".odt",
        ".ods",
        ".kmz",
    }
)


def header_is_zip_container_magic(header: bytes) -> bool:
    """Return True when the first bytes match a ZIP-family container magic."""
    return any(header.startswith(magic) for magic in ZIP_CONTAINER_MAGICS)


def sniff_zip_container(path: Path) -> bool:
    """A1 public probe: True when path bytes start with ZIP container magic."""
    try:
        with open(path, "rb") as handle:
            return header_is_zip_container_magic(handle.read(4))
    except OSError:
        return False
