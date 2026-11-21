"""Parsing and verification of unsigned ``.dsc`` source control files.

A source binding upload consists of one unsigned ``.dsc`` plus every source
file listed in its ``Checksums-Sha256`` paragraph.  The :rfc:`deb822` stanza is
parsed with the same strict parser used for binary package control files, and
each uploaded source file is matched against the manifest by *name, size and
SHA-256* — all three must agree.

The module also builds the deterministic tar archive returned to downloaders
and a stable fingerprint of the whole submission, so that re-uploading the
exact same originals is recognisable even when the multipart order changes.
"""

from __future__ import annotations

import hashlib
import io
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .deb import (
    PACKAGE_RE,
    VERSION_RE,
    DebError,
    parse_control_text,
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
#: File names inside a .dsc manifest are plain basenames.
_MANIFEST_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+~_-]*$")
_PGP_ARMOUR = b"-----BEGIN PGP SIGNED MESSAGE-----"


class DscError(ValueError):
    """Raised when an uploaded ``.dsc`` or its source files do not verify."""


@dataclass(frozen=True)
class ManifestEntry:
    """One ``Checksums-Sha256`` line: digest, byte size and file name."""

    sha256: str
    size: int
    name: str


@dataclass(frozen=True)
class DscInfo:
    source: str
    version: str
    entries: tuple[ManifestEntry, ...]
    raw: bytes
    sha256: str

    def manifest(self) -> dict[str, ManifestEntry]:
        return {entry.name: entry for entry in self.entries}


@dataclass(frozen=True)
class SourceIdentity:
    """The source package name/version derived from a binary ``.deb``."""

    package: str
    version: str


def is_digest(value: str) -> bool:
    return bool(_DIGEST_RE.fullmatch(value or ""))


def parse_source_field(value: str | None, binary_package: str, binary_version: str) -> SourceIdentity:
    """Apply the Debian ``Source`` field rules.

    ``Source: src-name`` or ``Source: src-name (src-version)``.  When the field
    is absent the binary package name and version are used, and a bare name
    without a parenthesised version likewise inherits the binary version.
    """

    if value is None or not value.strip():
        return SourceIdentity(binary_package, binary_version)
    text = value.strip()
    match = re.fullmatch(r"(\S+)(?:\s+\(([^()]+)\))?", text)
    if match is None:
        raise DscError(f"binary package has a malformed Source field: {text!r}")
    name, version = match.group(1), match.group(2)
    if not PACKAGE_RE.match(name):
        raise DscError(f"binary package has an invalid Source package name: {name!r}")
    if version is None:
        version = binary_version
    elif not VERSION_RE.match(version) or len(version) > 128:
        raise DscError(f"binary package has an invalid Source version: {version!r}")
    return SourceIdentity(name, version)


def parse_dsc(data: bytes) -> DscInfo:
    """Parse and validate an unsigned ``.dsc`` document."""

    if not data:
        raise DscError("the .dsc file is empty")
    if _PGP_ARMOUR in data:
        raise DscError("signed .dsc files are not accepted; upload an unsigned .dsc")
    if b"\x00" in data:
        raise DscError("the .dsc file contains NUL bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DscError("the .dsc file is not valid UTF-8") from exc

    try:
        fields = parse_control_text(text)
    except DebError as exc:
        raise DscError(f"malformed .dsc: {exc}") from exc
    lookup = {key.casefold(): value for key, value in fields}

    source = lookup.get("source")
    version = lookup.get("version")
    checksums = lookup.get("checksums-sha256")
    if not source:
        raise DscError("the .dsc must provide a Source field")
    if not PACKAGE_RE.match(source):
        raise DscError(f"the .dsc has an invalid Source package name: {source!r}")
    if not version or not VERSION_RE.match(version) or len(version) > 128:
        raise DscError(f"the .dsc has an invalid Version: {version!r}")
    if checksums is None or not checksums.strip():
        raise DscError("the .dsc must provide a Checksums-Sha256 paragraph")

    entries: list[ManifestEntry] = []
    seen: set[str] = set()
    for line in checksums.splitlines():
        body = line.strip()
        if not body:
            continue
        parts = body.split()
        if len(parts) != 3:
            raise DscError(
                "malformed Checksums-Sha256 line (expected '<sha256> <size> <name>'): "
                f"{body[:80]!r}"
            )
        digest, size_text, name = parts
        if not _HEX64_RE.fullmatch(digest):
            raise DscError(f"Checksums-Sha256 entry for {name!r} is not a SHA-256 digest")
        if not size_text.isdigit():
            raise DscError(f"Checksums-Sha256 entry for {name!r} has a non-numeric size")
        if "/" in name or not _MANIFEST_NAME_RE.fullmatch(name):
            raise DscError(f"Checksums-Sha256 lists an invalid file name: {name!r}")
        if name in seen:
            raise DscError(f"Checksums-Sha256 lists {name!r} more than once")
        seen.add(name)
        entries.append(ManifestEntry(sha256=digest, size=int(size_text), name=name))
    if not entries:
        raise DscError("the .dsc Checksums-Sha256 paragraph lists no source files")

    return DscInfo(
        source=source,
        version=version,
        entries=tuple(entries),
        raw=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def safe_basename(filename: str) -> str:
    """Return the upload's basename, rejecting any path component."""

    name = Path(filename).name
    if name != filename or name in ("", ".", "..") or "\x00" in name:
        raise DscError(f"unsafe upload file name: {filename!r}")
    return name


def verify_source_files(
    dsc: DscInfo, files: dict[str, bytes]
) -> dict[str, ManifestEntry]:
    """Match every uploaded source file against the manifest.

    *files* maps basename to exact bytes.  Every manifest entry must have a
    matching upload and vice versa; name, size and SHA-256 must all agree.
    """

    manifest = dsc.manifest()
    if set(files) != set(manifest):
        missing = sorted(set(manifest) - set(files))
        extra = sorted(set(files) - set(manifest))
        details = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if extra:
            details.append(f"not listed in Checksums-Sha256: {', '.join(extra)}")
        raise DscError("uploaded source files do not match the .dsc manifest; " + "; ".join(details))

    resolved: dict[str, ManifestEntry] = {}
    for name, data in files.items():
        entry = manifest[name]
        actual_size = len(data)
        if actual_size != entry.size:
            raise DscError(
                f"{name}: size {actual_size} does not match the .dsc manifest ({entry.size})"
            )
        actual_digest = hashlib.sha256(data).hexdigest()
        if actual_digest != entry.sha256:
            raise DscError(
                f"{name}: SHA-256 {actual_digest} does not match the .dsc manifest"
            )
        resolved[name] = entry
    return resolved


def binding_fingerprint(dsc: DscInfo) -> str:
    """Stable identity of a whole submission.

    Two submissions are the same originals iff their .dsc bytes and the
    manifest (names, sizes, digests) are identical; multipart order is ignored.
    """

    hasher = hashlib.sha256()
    hasher.update(b"source-binding-v1\n")
    hasher.update(f"dsc {dsc.sha256}\n".encode("ascii"))
    for entry in sorted(dsc.entries, key=lambda item: item.name):
        hasher.update(
            f"{entry.sha256} {entry.size} {entry.name}\n".encode("ascii")
        )
    return hasher.hexdigest()


def build_archive(
    *, dsc_name: str, dsc: DscInfo, files: dict[str, bytes]
) -> bytes:
    """Build the deterministic, flat tar archive returned to downloaders.

    The original .dsc bytes and every source file are stored under their
    original basenames.  Fixed metadata (mtime 0, uid/gid 0, sorted names)
    makes the archive reproducible byte for byte.
    """

    members = [(dsc_name, dsc.raw)]
    members.extend(sorted(files.items()))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:", format=tarfile.GNU_FORMAT) as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()
