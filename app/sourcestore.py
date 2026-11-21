"""Durable storage for source-package bindings.

A *binding* maps one binary package (identified by its SHA-256) to the exact
source submission registered by its builder: the original unsigned ``.dsc``
plus every file listed in ``Checksums-Sha256``, packaged as one tar archive.

Bindings live outside the APT document tree (``data/sources/`` rather than
``data/export/``), so repository garbage collection can never reclaim them —
once a binding is committed its archive stays downloadable even after the
binary package itself has been evicted and the service has restarted.

Transaction protocol
--------------------
1. All validation (``.dsc`` parsing, manifest matching, identity checks) runs
   before any state change and without holding the publication lock, so uploads
   never block ordinary ``.deb`` publications.
2. Under the shared publication lock the retained-publication reference is
   re-checked and the journal is consulted for an existing binding.
3. A ``staged`` row is inserted, the archive is written atomically and fsynced,
   and only then is the row marked ``committed`` — the row is the sole
   download gate, so a crash mid-write never exposes a partial archive.
4. Re-uploading the same originals returns the original address; a different
   submission for an already-bound digest raises :class:`BindingConflict`.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .config import Settings
from .deb import DebError, read_deb_control
from .dsc import (
    DscError,
    DscInfo,
    ManifestEntry,
    binding_fingerprint,
    build_archive,
    parse_dsc,
    parse_source_field,
    verify_source_files,
)
from .storage import (
    FileLease,
    Repository,
    _fsync_dir,
    atomic_write,
    sha256_file,
)


class BindingConflict(Exception):
    """The digest is already bound to a different source submission."""


@dataclass(frozen=True)
class SourceBinding:
    binary_sha256: str
    source_name: str
    source_version: str
    dsc_name: str
    dsc_sha256: str
    fingerprint: str
    archive_sha256: str
    archive_size: int
    created_at: str
    download_url: str

    def to_dict(self) -> dict[str, object]:
        return {
            "binary_sha256": self.binary_sha256,
            "source": self.source_name,
            "source_version": self.source_version,
            "dsc": self.dsc_name,
            "dsc_sha256": self.dsc_sha256,
            "fingerprint": self.fingerprint,
            "archive_sha256": self.archive_sha256,
            "archive_size": self.archive_size,
            "created_at": self.created_at,
            "download_url": self.download_url,
        }


def _utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SourceStore:
    def __init__(self, settings: Settings, repository: Repository) -> None:
        self.settings = settings
        self.repository = repository
        self.root = settings.data_dir / "sources"
        self.archives = self.root / "archives"
        self.db_path = settings.data_dir / "state.sqlite3"
        self.root.mkdir(parents=True, exist_ok=True)
        self.archives.mkdir(parents=True, exist_ok=True)
        self._initialise()
        self.reconcile()

    # --------------------------------------------------------------- database
    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
        finally:
            db.close()

    def _initialise(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_bindings (
                    binary_sha256 TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    source_version TEXT NOT NULL,
                    dsc_name TEXT NOT NULL,
                    dsc_sha256 TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    archive_size INTEGER NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('staged','committed'))
                );
                """
            )

    def _archive_path(self, digest: str) -> Path:
        return self.archives / f"{digest}.tar"

    def download_url(self, digest: str) -> str:
        return f"/api/sources/{digest}"

    def _row_to_binding(self, row: sqlite3.Row) -> SourceBinding:
        return SourceBinding(
            binary_sha256=row["binary_sha256"],
            source_name=row["source_name"],
            source_version=row["source_version"],
            dsc_name=row["dsc_name"],
            dsc_sha256=row["dsc_sha256"],
            fingerprint=row["fingerprint"],
            archive_sha256=row["archive_sha256"],
            archive_size=row["archive_size"],
            created_at=row["created_at"],
            download_url=self.download_url(row["binary_sha256"]),
        )

    # -------------------------------------------------------------- recovery
    def reconcile(self) -> None:
        """Roll back interrupted writes and remove orphaned archive files."""

        with self._connect() as db:
            staged = db.execute(
                "SELECT binary_sha256 FROM source_bindings WHERE state='staged'"
            ).fetchall()
            for row in staged:
                digest = row["binary_sha256"]
                db.execute(
                    "DELETE FROM source_bindings WHERE binary_sha256=? AND state='staged'",
                    (digest,),
                )
                with contextlib.suppress(OSError):
                    self._archive_path(digest).unlink()
            committed = {
                row["binary_sha256"]
                for row in db.execute(
                    "SELECT binary_sha256 FROM source_bindings WHERE state='committed'"
                ).fetchall()
            }
        for path in self.archives.glob("*.tar"):
            digest = path.name[: -len(".tar")]
            if digest not in committed:
                with contextlib.suppress(OSError):
                    path.unlink()
        for tmp in self.archives.glob(".*.tmp"):
            with contextlib.suppress(OSError):
                tmp.unlink()

    # ---------------------------------------------------------------- binding
    def validate(
        self,
        digest: str,
        dsc_name: str,
        dsc_bytes: bytes,
        files: dict[str, bytes],
    ) -> tuple[DscInfo, dict[str, ManifestEntry], str, bytes, str, str]:
        """Run every check that needs no lock and touches no binding state."""

        # The retention rule is evaluated first: an evicted or unknown binary
        # is a conflict regardless of how well-formed the submission is.
        found = self.repository.find_retained_package(digest)
        if found is None:
            raise BindingConflict(
                f"binary package {digest} has no retained publication reference; "
                "its .deb must still be published before sources can be bound"
            )
        deb_path: Path = found["path"]  # type: ignore[assignment]

        dsc = parse_dsc(dsc_bytes)
        verify_source_files(dsc, files)
        fingerprint = binding_fingerprint(dsc)
        archive = build_archive(dsc_name=dsc_name, dsc=dsc, files=files)

        try:
            info = read_deb_control(deb_path, self.settings.architecture)
        except DebError as exc:
            raise DscError(f"cannot read control data of the referenced .deb: {exc}") from exc
        identity = parse_source_field(
            info.field_map().get("Source"), info.package, info.version
        )
        if dsc.source != identity.package:
            raise DscError(
                f".dsc Source {dsc.source!r} does not match the .deb source "
                f"package {identity.package!r}"
            )
        if dsc.version != identity.version:
            raise DscError(
                f".dsc Version {dsc.version!r} does not match the .deb source "
                f"version {identity.version!r}"
            )
        return dsc, files, fingerprint, archive, identity.package, identity.version

    def bind(
        self,
        digest: str,
        dsc_name: str,
        dsc_bytes: bytes,
        files: dict[str, bytes],
    ) -> SourceBinding:
        # Expensive validation first, and without serialising against publish.
        dsc, _verified, fingerprint, archive, source_name, source_version = (
            self.validate(digest, dsc_name, dsc_bytes, files)
        )
        archive_sha = hashlib.sha256(archive).hexdigest()
        created_at = _utcnow()
        target = self._archive_path(digest)

        with self.repository._exclusive():
            # The retained set may have changed while validation was running.
            if self.repository.find_retained_package(digest) is None:
                raise BindingConflict(
                    f"binary package {digest} lost its retained publication "
                    "reference before the binding committed"
                )
            with self._connect() as db:
                existing = db.execute(
                    "SELECT * FROM source_bindings WHERE binary_sha256=?",
                    (digest,),
                ).fetchone()
            if existing is not None:
                if existing["fingerprint"] == fingerprint:
                    return self._row_to_binding(existing)
                raise BindingConflict(
                    f"binary package {digest} is already bound to a different "
                    "source submission"
                )

            with self._connect() as db:
                db.execute(
                    "INSERT INTO source_bindings (binary_sha256, created_at, "
                    "source_name, source_version, dsc_name, dsc_sha256, "
                    "fingerprint, archive_sha256, archive_size, state) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged')",
                    (
                        digest,
                        created_at,
                        source_name,
                        source_version,
                        dsc_name,
                        dsc.sha256,
                        fingerprint,
                        archive_sha,
                        len(archive),
                    ),
                )
            try:
                atomic_write(target, archive)
                with self._connect() as db:
                    db.execute(
                        "UPDATE source_bindings SET state='committed' "
                        "WHERE binary_sha256=? AND state='staged'",
                        (digest,),
                    )
                _fsync_dir(self.archives)
            except BaseException:
                with contextlib.suppress(Exception):
                    target.unlink()
                with self._connect() as db:
                    db.execute(
                        "DELETE FROM source_bindings WHERE binary_sha256=? "
                        "AND state='staged'",
                        (digest,),
                    )
                raise

        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM source_bindings WHERE binary_sha256=?", (digest,)
            ).fetchone()
        assert row is not None
        return self._row_to_binding(row)

    # ---------------------------------------------------------------- reads
    def get_binding(self, digest: str) -> SourceBinding | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT * FROM source_bindings WHERE binary_sha256=? AND state='committed'",
                (digest,),
            ).fetchone()
        return self._row_to_binding(row) if row else None

    def list_bindings(self, limit: int = 100) -> list[SourceBinding]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT * FROM source_bindings WHERE state='committed' "
                "ORDER BY created_at DESC, binary_sha256 DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_binding(row) for row in rows]

    def open_archive(self, digest: str) -> FileLease | None:
        """Open a committed archive for streaming, or ``None`` if absent."""

        binding = self.get_binding(digest)
        if binding is None:
            return None
        path = self._archive_path(digest)
        try:
            fh = path.open("rb")
        except OSError:
            return None
        try:
            stat_result = os.fstat(fh.fileno())
            return FileLease(
                fh=fh,
                size=stat_result.st_size,
                relpath=str(path.relative_to(self.settings.data_dir)),
                last_modified=stat_result.st_mtime,
                etag=f'"{binding.archive_sha256}"',
            )
        except OSError:
            fh.close()
            return None

    def verify_archive_on_disk(self, digest: str) -> bool:
        """Test helper: prove the stored archive matches the journal digest."""

        binding = self.get_binding(digest)
        path = self._archive_path(digest)
        if binding is None or not path.is_file():
            return False
        return sha256_file(path) == binding.archive_sha256
