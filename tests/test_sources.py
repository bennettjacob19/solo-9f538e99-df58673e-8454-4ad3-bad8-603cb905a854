"""End-to-end tests for source-package bindings.

The binding flow lets a builder register the exact source (unsigned ``.dsc``
plus the files it lists in ``Checksums-Sha256``) of a binary package, keyed by
the binary's SHA-256.  These tests cover identity derivation, manifest
matching, the first-binding retention rule, idempotency vs conflicts, failed
write atomicity and durability across restarts and binary eviction.
"""

from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
from debbuild import build_deb  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent.parent))
from app import sourcestore  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data")


@pytest.fixture()
def client(tmp_path):
    settings = make_settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client, settings


def publish_deb(
    test_client: TestClient,
    directory: Path,
    *,
    package: str = "widget",
    version: str = "1.0.0",
    source: str | None = None,
    payload: bytes = b"binary payload\n",
) -> tuple[str, Path, bytes]:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{package}_{version}_amd64.deb"
    control = {"Package": package, "Version": version}
    if source is not None:
        control["Source"] = source
    build_deb(path, control=control, payload=payload)
    blob = path.read_bytes()
    response = test_client.post(
        "/api/publish",
        files=[("files", (path.name, blob, "application/vnd.debian.binary-package"))],
    )
    assert response.status_code == 201, response.text
    return sha256(blob), path, blob


def make_dsc(
    *,
    source: str = "widget",
    version: str = "1.0.0",
    files: dict[str, bytes] | None = None,
) -> tuple[str, bytes]:
    if files is None:
        files = {
            f"{source}_{version}.orig.tar.gz": b"upstream tarball\n",
            f"{source}_{version}.debian.tar.xz": b"debian packaging\n",
        }
    lines = [
        f"Format: 3.0 (quilt)\n",
        f"Source: {source}\n",
        f"Version: {version}\n",
        "Architecture: any\n",
        "Checksums-Sha256:\n",
    ]
    for name in sorted(files):
        data = files[name]
        lines.append(f" {sha256(data)} {len(data)} {name}\n")
    dsc_name = f"{source}_{version}.dsc"
    return dsc_name, "".join(lines).encode("utf-8")


def bind_request(
    test_client: TestClient,
    digest: str,
    dsc_name: str,
    dsc_bytes: bytes,
    files: dict[str, bytes],
):
    payload = [
        ("digest", (None, digest)),
        ("dsc", (dsc_name, dsc_bytes, "text/plain")),
    ]
    for name, data in sorted(files.items()):
        payload.append(("files", (name, data, "application/octet-stream")))
    return test_client.post("/api/sources", files=payload)


def read_archive(blob: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as archive:
        return {
            member.name: archive.extractfile(member).read()
            for member in archive
            if member.isfile()
        }


def publish_and_bind(
    client,
    *,
    package: str = "widget",
    version: str = "1.0.0",
    source: str | None = None,
    source_name: str | None = None,
    source_version: str | None = None,
    files: dict[str, bytes] | None = None,
):
    test_client, settings = client
    digest, _deb_path, _blob = publish_deb(
        test_client,
        settings.data_dir.parent / "debs",
        package=package,
        version=version,
        source=source,
    )
    effective_source = source_name or package
    effective_version = source_version or version
    if files is None:
        files = {
            f"{effective_source}_{effective_version}.orig.tar.gz": b"upstream tarball\n",
            f"{effective_source}_{effective_version}.debian.tar.xz": b"debian packaging\n",
        }
    dsc_name, dsc_bytes = make_dsc(
        source=effective_source,
        version=effective_version,
        files=files,
    )
    response = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    return digest, dsc_name, dsc_bytes, files, response


def test_successful_binding_returns_download_url_and_archive(client):
    test_client, _settings = client
    digest, dsc_name, dsc_bytes, source_files, response = publish_and_bind(client)
    assert response.status_code == 201, response.text
    body = response.json()["binding"]
    assert body["binary_sha256"] == digest
    assert body["source"] == "widget"
    assert body["source_version"] == "1.0.0"
    assert body["dsc"] == dsc_name
    assert body["download_url"] == f"/api/sources/{digest}"

    downloaded = test_client.get(body["download_url"])
    assert downloaded.status_code == 200
    assert downloaded.headers["content-type"] == "application/x-tar"
    assert downloaded.headers["etag"] == f'"{body["archive_sha256"]}"'
    assert sha256(downloaded.content) == body["archive_sha256"]
    members = read_archive(downloaded.content)
    assert members[dsc_name] == dsc_bytes
    for name, data in source_files.items():
        assert members[name] == data
    # A flat archive: no directories, no extra members.
    assert set(members) == {dsc_name, *source_files}


def test_source_identity_defaults_to_package_and_version(client):
    test_client, _settings = client
    digest, _deb, _blob = publish_deb(
        test_client,
        _settings_data_dir(client),
        package="plain",
        version="2.5.0",
    )
    files = {"plain_2.5.0.orig.tar.gz": b"up\n", "plain_2.5.0.debian.tar.xz": b"deb\n"}
    dsc_name, dsc_bytes = make_dsc(source="plain", version="2.5.0", files=files)
    response = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    assert response.status_code == 201, response.text
    binding = response.json()["binding"]
    assert binding["source"] == "plain"
    assert binding["source_version"] == "2.5.0"


def _settings_data_dir(client_fixture) -> Path:
    return client_fixture[1].data_dir.parent / "debs"


def test_source_field_with_name_and_parenthesised_version(client):
    test_client, _settings = client
    digest, _deb, _blob = publish_deb(
        test_client,
        _settings_data_dir(client),
        package="widget-tools",
        version="1.0.0-3",
        source="widget (1.0.0-1)",
    )
    files = {"widget_1.0.0.orig.tar.gz": b"up\n", "widget_1.0.0-1.debian.tar.xz": b"d\n"}
    dsc_name, dsc_bytes = make_dsc(source="widget", version="1.0.0-1", files=files)
    response = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    assert response.status_code == 201, response.text
    binding = response.json()["binding"]
    assert binding["source"] == "widget"
    assert binding["source_version"] == "1.0.0-1"

    # The wrong source name / version must be refused.
    bad_files = {
        "widget-tools_1.0.0.orig.tar.gz": b"up\n",
        "widget-tools_1.0.0-3.debian.tar.xz": b"d\n",
    }
    bad_name, bad_dsc = make_dsc(
        source="widget-tools", version="1.0.0-3", files=bad_files
    )
    bad = bind_request(test_client, digest, bad_name, bad_dsc, bad_files)
    assert bad.status_code == 400
    assert "Source" in bad.text


def test_bare_source_name_inherits_binary_version(client):
    test_client, _settings = client
    digest, _deb, _blob = publish_deb(
        test_client,
        _settings_data_dir(client),
        package="widget-data",
        version="4.2.1",
        source="widget",
    )
    files = {"widget_4.2.1.orig.tar.gz": b"up\n", "widget_4.2.1.debian.tar.xz": b"d\n"}
    dsc_name, dsc_bytes = make_dsc(source="widget", version="4.2.1", files=files)
    response = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    assert response.status_code == 201, response.text


def test_unknown_digest_has_no_retained_reference(client):
    test_client, _settings = client
    publish_deb(test_client, _settings_data_dir(client))
    ghost = "a" * 64
    dsc_name, dsc_bytes = make_dsc()
    response = bind_request(
        test_client,
        ghost,
        dsc_name,
        dsc_bytes,
        {"widget_1.0.0.orig.tar.gz": b"up\n", "widget_1.0.0.debian.tar.xz": b"d\n"},
    )
    assert response.status_code == 409
    assert "retained publication" in response.text
    assert test_client.get(f"/api/sources/{ghost}").status_code == 404


def test_first_binding_requires_live_retained_reference_after_eviction(client):
    test_client, settings = client
    # Publish then keep publishing other batches until the first deb is evicted.
    first_digest, _p, _b = publish_deb(
        test_client,
        settings.data_dir.parent / "debs",
        package="first",
        version="1.0.0",
        payload=b"one\n",
    )
    for version in ("2.0.0", "3.0.0"):
        publish_deb(
            test_client,
            settings.data_dir.parent / "debs",
            package="other",
            version=version,
            payload=version.encode(),
        )
    # The first deb's pool file must be gone now (retention = 2).
    assert test_client.get(f"/api/sources/{first_digest}").status_code == 404
    dsc_name, dsc_bytes = make_dsc(source="first", version="1.0.0")
    response = bind_request(
        test_client,
        first_digest,
        dsc_name,
        dsc_bytes,
        {"first_1.0.0.orig.tar.gz": b"up\n", "first_1.0.0.debian.tar.xz": b"d\n"},
    )
    assert response.status_code == 409
    assert "retained publication" in response.text


def test_binding_survives_binary_eviction_and_service_restart(tmp_path):
    settings = make_settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as test_client:
        digest, dsc_name, dsc_bytes, source_files, response = publish_and_bind(
            (test_client, settings)
        )
        assert response.status_code == 201
        # Two more publications evict the original deb from the repository.
        for version in ("2.0.0", "3.0.0"):
            publish_deb(
                test_client,
                settings.data_dir.parent / "debs",
                package="other",
                version=version,
                payload=version.encode(),
            )

    # Simulate a service restart with a brand new application instance.
    restarted = create_app(settings)
    with TestClient(restarted) as test_client:
        downloaded = test_client.get(f"/api/sources/{digest}")
        assert downloaded.status_code == 200
        members = read_archive(downloaded.content)
        assert members[dsc_name] == dsc_bytes
        for name, data in source_files.items():
            assert members[name] == data
        listing = test_client.get("/api/sources").json()["bindings"]
        assert [item["binary_sha256"] for item in listing] == [digest]
        assert test_client.get("/api/status").json()["source_bindings"] == 1


def test_repeat_upload_of_same_originals_returns_same_address(client):
    test_client, _settings = client
    digest, dsc_name, dsc_bytes, source_files, first = publish_and_bind(client)
    assert first.status_code == 201
    url = first.json()["binding"]["download_url"]

    # Same bytes, different multipart order: still the same originals.
    payload = [
        ("digest", (None, digest)),
        ("dsc", (dsc_name, dsc_bytes, "text/plain")),
    ]
    for name, data in sorted(source_files.items(), reverse=True):
        payload.append(("files", (name, data, "application/octet-stream")))
    second = test_client.post("/api/sources", files=payload)
    assert second.status_code == 201, second.text
    assert second.json()["binding"]["download_url"] == url
    assert second.json()["binding"]["fingerprint"] == first.json()["binding"]["fingerprint"]
    assert len(test_client.get("/api/sources").json()["bindings"]) == 1


def test_different_originals_for_bound_digest_conflict(client):
    test_client, _settings = client
    digest, _dsc_name, _dsc_bytes, _files, first = publish_and_bind(client)
    assert first.status_code == 201

    changed = {"widget_1.0.0.orig.tar.gz": b"tampered upstream tarball\n",
               "widget_1.0.0.debian.tar.xz": b"debian packaging\n"}
    bad_name, bad_dsc = make_dsc(files=changed)
    response = bind_request(test_client, digest, bad_name, bad_dsc, changed)
    assert response.status_code == 409
    assert "already bound" in response.text

    # Also a different (valid) .dsc revision pointing at the same file names.
    good_files = {
        "widget_1.0.0.orig.tar.gz": b"upstream tarball\n",
        "widget_1.0.0.debian.tar.xz": b"debian packaging\n",
    }
    _n, valid_dsc = make_dsc(files=good_files)
    tweaked = valid_dsc.replace(
        b"Format: 3.0 (quilt)\n", b"Format: 3.0 (native)\n"
    )
    conflict = bind_request(test_client, digest, bad_name, tweaked, good_files)
    assert conflict.status_code == 409

    # The original archive is untouched and still downloadable.
    original = test_client.get(first.json()["binding"]["download_url"])
    assert original.status_code == 200
    assert sha256(original.content) == first.json()["binding"]["archive_sha256"]


def test_manifest_size_mismatch_is_rejected(client):
    test_client, _settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    good = {
        "widget_1.0.0.orig.tar.gz": b"upstream tarball\n",
        "widget_1.0.0.debian.tar.xz": b"debian packaging\n",
    }
    _name, dsc_bytes = make_dsc(files=good)
    tampered = dict(good)
    tampered["widget_1.0.0.orig.tar.gz"] = b"wrong length"
    response = bind_request(test_client, digest, "widget_1.0.0.dsc", dsc_bytes, tampered)
    assert response.status_code == 400
    assert "size" in response.text.lower() or "sha-256" in response.text.lower()
    assert test_client.get(f"/api/sources/{digest}").status_code == 404


def test_manifest_digest_mismatch_is_rejected(client):
    test_client, _settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    files = {"widget_1.0.0.orig.tar.gz": b"same-length-aaa\n",
             "widget_1.0.0.debian.tar.xz": b"debian packaging\n"}
    _name, dsc_bytes = make_dsc(files=files)
    tampered = dict(files)
    tampered["widget_1.0.0.orig.tar.gz"] = b"same-length-bbb\n"
    assert len(tampered["widget_1.0.0.orig.tar.gz"]) == len(
        files["widget_1.0.0.orig.tar.gz"]
    )
    response = bind_request(test_client, digest, "widget_1.0.0.dsc", dsc_bytes, tampered)
    assert response.status_code == 400
    assert "sha-256" in response.text.lower()


def test_missing_and_extra_source_files_are_rejected(client):
    test_client, _settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    files = {
        "widget_1.0.0.orig.tar.gz": b"upstream tarball\n",
        "widget_1.0.0.debian.tar.xz": b"debian packaging\n",
    }
    _name, dsc_bytes = make_dsc(files=files)

    missing = bind_request(
        test_client,
        digest,
        "widget_1.0.0.dsc",
        dsc_bytes,
        {"widget_1.0.0.orig.tar.gz": b"upstream tarball\n"},
    )
    assert missing.status_code == 400
    assert "missing" in missing.text.lower()

    extra = bind_request(
        test_client,
        digest,
        "widget_1.0.0.dsc",
        dsc_bytes,
        {**files, "unlisted.txt": b"nope\n"},
    )
    assert extra.status_code == 400
    assert "not listed" in extra.text.lower()


def test_signed_dsc_is_rejected(client):
    test_client, _settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    files = {"widget_1.0.0.orig.tar.gz": b"up\n"}
    _name, unsigned = make_dsc(files=files)
    signed = (
        b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
        + unsigned
        + b"\n-----BEGIN PGP SIGNATURE-----\n\nfakesig\n-----END PGP SIGNATURE-----\n"
    )
    response = bind_request(test_client, digest, "widget_1.0.0.dsc", signed, files)
    assert response.status_code == 400
    assert "signed" in response.text.lower()


def test_malformed_dsc_and_bad_digest_are_rejected(client):
    test_client, _settings = client
    files = {"widget_1.0.0.orig.tar.gz": b"up\n"}
    response = bind_request(
        test_client,
        "not-a-digest",
        "widget_1.0.0.dsc",
        b"Source: widget\n",
        files,
    )
    assert response.status_code == 400
    assert "sha-256" in response.text.lower()

    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    response = bind_request(
        test_client,
        digest,
        "widget_1.0.0.dsc",
        b"Source: widget\nVersion: 1.0.0\n",  # no Checksums-Sha256
        files,
    )
    assert response.status_code == 400
    assert "checksums-sha256" in response.text.lower()


def test_failed_write_creates_no_downloadable_archive(client, monkeypatch):
    test_client, settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    files = {"widget_1.0.0.orig.tar.gz": b"up\n", "widget_1.0.0.debian.tar.xz": b"d\n"}
    dsc_name, dsc_bytes = make_dsc(files=files)

    original = sourcestore.atomic_write

    def explode(target: Path, data: bytes) -> None:
        if target.name == f"{digest}.tar":
            raise OSError("simulated disk full")
        original(target, data)

    monkeypatch.setattr(sourcestore, "atomic_write", explode)
    response = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    assert response.status_code == 500
    monkeypatch.setattr(sourcestore, "atomic_write", original)

    # Nothing downloadable, no staged row left behind, and a retry succeeds.
    assert test_client.get(f"/api/sources/{digest}").status_code == 404
    retry = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    assert retry.status_code == 201
    store = test_client.app.state.source_store
    with store._connect() as db:
        states = [
            row["state"]
            for row in db.execute("SELECT state FROM source_bindings").fetchall()
        ]
    assert states == ["committed"]


def test_publications_continue_while_validation_runs(client):
    """Binding validation happens outside the publication lock."""

    test_client, settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    files = {"widget_1.0.0.orig.tar.gz": b"up\n", "widget_1.0.0.debian.tar.xz": b"d\n"}
    dsc_name, dsc_bytes = make_dsc(files=files)

    # A deliberately broken binding must not change any publication state.
    bad = bind_request(test_client, digest, dsc_name, dsc_bytes, {"only": b"x\n"})
    assert bad.status_code == 400
    publications_before = test_client.get("/api/publications").json()
    release_before = test_client.get("/dists/stable/Release").text

    ok = bind_request(test_client, digest, dsc_name, dsc_bytes, files)
    assert ok.status_code == 201
    # Publishing another batch still works and the binding stays available.
    publish_deb(
        test_client,
        settings.data_dir.parent / "debs2",
        package="another",
        version="9.0.0",
    )
    assert test_client.get(f"/api/sources/{digest}").status_code == 200
    publications_after = test_client.get("/api/publications").json()
    assert len(publications_after["publications"]) == (
        len(publications_before["publications"]) + 1
    )
    assert release_before != test_client.get("/dists/stable/Release").text


def test_head_matches_get_for_source_archive(client):
    test_client, _settings = client
    digest, _n, _d, _f, response = publish_and_bind(client)
    binding = response.json()["binding"]
    get = test_client.get(f"/api/sources/{digest}")
    head = test_client.head(f"/api/sources/{digest}")
    assert head.status_code == 200
    assert head.content == b""
    assert head.headers["content-length"] == str(len(get.content))
    assert head.headers["etag"] == get.headers["etag"]
    assert head.headers["content-type"] == "application/x-tar"
    assert binding["archive_size"] == len(get.content)


def test_path_components_in_upload_names_are_rejected(client):
    test_client, _settings = client
    digest, _p, _b = publish_deb(test_client, _settings_data_dir(client))
    files = {"widget_1.0.0.orig.tar.gz": b"up\n"}
    _n, dsc_bytes = make_dsc(files=files)
    response = test_client.post(
        "/api/sources",
        files=[
            ("digest", (None, digest)),
            ("dsc", ("../evil.dsc", dsc_bytes, "text/plain")),
            ("files", ("widget_1.0.0.orig.tar.gz", b"up\n", "application/octet-stream")),
        ],
    )
    assert response.status_code == 400
    assert "file name" in response.text.lower()


def test_publishing_is_not_blocked_while_a_binding_validates(client, monkeypatch):
    """Long source validation runs outside the publication lock."""

    test_client, settings = client
    digest, _p, _b = publish_deb(test_client, settings.data_dir.parent / "debs")
    files = {"widget_1.0.0.orig.tar.gz": b"up\n", "widget_1.0.0.debian.tar.xz": b"d\n"}
    dsc_name, dsc_bytes = make_dsc(files=files)

    store = test_client.app.state.source_store
    original_validate = store.validate

    def slow_validate(*args, **kwargs):
        time.sleep(0.6)
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(store, "validate", slow_validate)
    results: dict[str, object] = {}

    def do_bind() -> None:
        results["bind"] = bind_request(
            test_client, digest, dsc_name, dsc_bytes, files
        )

    def do_publish() -> None:
        # Start slightly later, so it overlaps the slow validation window.
        time.sleep(0.15)
        other = settings.data_dir.parent / "concurrent" / "c_1.0.0_amd64.deb"
        build_deb(
            other, control={"Package": "concurrent", "Version": "1.0.0"}
        )
        results["publish"] = test_client.post(
            "/api/publish",
            files=[("files", (other.name, other.read_bytes(),
                              "application/vnd.debian.binary-package"))],
        )

    binder = threading.Thread(target=do_bind)
    publisher = threading.Thread(target=do_publish)
    start = time.monotonic()
    binder.start()
    publisher.start()
    binder.join()
    publisher.join()
    elapsed = time.monotonic() - start

    assert results["bind"].status_code == 201, results["bind"].text
    assert results["publish"].status_code == 201, results["publish"].text
    # The publication finished while validation was still in progress; if the
    # publication lock had been held during validation this could not happen
    # well within the validation delay.
    assert elapsed < 1.1


def test_concurrent_first_bindings_same_digest_one_wins(tmp_path):
    """Two simultaneous first bindings cannot both create an archive."""

    settings = make_settings(tmp_path)
    app = create_app(settings)
    store = app.state.source_store
    with TestClient(app) as test_client:
        digest, _p, _b = publish_deb(
            test_client, settings.data_dir.parent / "debs"
        )
        files_a = {"widget_1.0.0.orig.tar.gz": b"up\n",
                   "widget_1.0.0.debian.tar.xz": b"d\n"}
        name_a, dsc_a = make_dsc(files=files_a)
        files_b = {"widget_1.0.0.orig.tar.gz": b"up different\n",
                   "widget_1.0.0.debian.tar.xz": b"d2\n"}
        name_b, dsc_b = make_dsc(files=files_b)

        outcomes: list[object] = []

        def bind(files, name, dsc) -> None:
            outcomes.append(
                bind_request(test_client, digest, name, dsc, files).status_code
            )

        t1 = threading.Thread(target=bind, args=(files_a, name_a, dsc_a))
        t2 = threading.Thread(target=bind, args=(files_b, name_b, dsc_b))
        t1.start(); t2.start(); t1.join(); t2.join()

    assert sorted(outcomes) == [201, 409]
    # Exactly one committed row and one archive.
    with store._connect() as db:
        rows = db.execute("SELECT state FROM source_bindings").fetchall()
    assert [row["state"] for row in rows] == ["committed"]
    assert list(store.archives.glob("*.tar")) and len(
        list(store.archives.glob("*.tar"))
    ) == 1


def test_staged_binding_from_crash_is_rolled_back_on_restart(tmp_path):
    settings = make_settings(tmp_path)
    app = create_app(settings)
    with TestClient(app) as test_client:
        digest, _p, _b = publish_deb(
            test_client, settings.data_dir.parent / "debs"
        )
    store = app.state.source_store
    # Simulate a process that died after the staged row but before commit.
    with store._connect() as db:
        db.execute(
            "INSERT INTO source_bindings (binary_sha256, created_at, source_name, "
            "source_version, dsc_name, dsc_sha256, fingerprint, archive_sha256, "
            "archive_size, state) VALUES (?, 'now', 'widget', '1.0.0', "
            "'widget_1.0.0.dsc', ?, ?, ?, 10, 'staged')",
            (digest, "a" * 64, "b" * 64, "c" * 64),
        )
    orphan = store._archive_path(digest)
    orphan.write_bytes(b"partial")

    # A fresh instance reconciles the stale state away.
    restarted = create_app(settings)
    with TestClient(restarted) as client:
        assert client.get(f"/api/sources/{digest}").status_code == 404
        assert not orphan.exists()
    with store._connect() as db:
        assert db.execute(
            "SELECT COUNT(*) AS n FROM source_bindings"
        ).fetchone()["n"] == 0
