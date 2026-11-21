"""FastAPI application exposing an atomic, by-hash enabled APT repository.

Routes
------
``GET  /docs``                      interactive upload forms
``POST /api/publish``               upload a batch of ``.deb`` files and publish
``POST /api/sources``               bind an unsigned ``.dsc`` + source files to a .deb hash
``GET  /api/sources/{sha256}``      download the source archive of a binding
``GET  /api/status``                repository state and publication history
``GET  /dists/...``, ``GET /pool/...``  the APT document tree (read-only)
``GET  /``                          plain-text instructions / sources.list
``GET  /swagger-ui``                generated OpenAPI documentation

Every upload is written to a private intake directory, validated and hashed,
and only then committed under a lock.  See :mod:`app.storage` and
:mod:`app.sourcestore` for the transaction and recovery protocols.
"""

from __future__ import annotations

import shutil
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from email.utils import formatdate
from pathlib import Path
from typing import Annotated

import anyio

from fastapi import (
    FastAPI,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.background import BackgroundTask

from .config import Settings
from .dsc import DscError, is_digest, safe_basename
from .sourcestore import BindingConflict, SourceStore
from .storage import PublicationError, Repository, StagedUpload

#: Content types Debian clients expect for the repository documents.
_MEDIA_TYPES = {
    "Release": "text/plain; charset=utf-8",
    "Packages": "text/plain; charset=utf-8",
    "Packages.gz": "application/gzip",
    "InRelease": "text/plain; charset=utf-8",
    "Release.gpg": "application/pgp-signature",
}

UPLOAD_FORM = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>APT repository upload</title>
<style>
 body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 52rem; }}
 code, pre {{ background: #f4f4f4; padding: .1rem .3rem; border-radius: 3px; }}
 pre {{ padding: .8rem; overflow-x: auto; }}
 form {{ border: 1px solid #ccc; padding: 1rem; border-radius: 6px; margin-bottom: 2rem; }}
 button {{ margin-top: .6rem; padding: .4rem 1rem; }}
 .hint {{ color: #555; }}
 h2 {{ margin-top: 2rem; }}
</style></head><body>
<h1>APT repository upload</h1>
<p>Suite <code>{suite}</code>, component <code>{component}</code>,
 architecture <code>{architecture}</code>.</p>
<p class="hint">Upload a complete batch of <code>.deb</code> files. The new
Release becomes visible only after every package has been validated and all
indexes are on disk; the two most recent publications stay downloadable.</p>
<form method="post" action="/api/publish" enctype="multipart/form-data">
  <label>Package files<br>
  <input type="file" name="files" multiple accept=".deb" required></label><br>
  <button type="submit">Publish</button>
</form>

<h2>Bind source to a binary package</h2>
<p class="hint">Given the SHA-256 of a still-published <code>.deb</code>,
 upload its builder-registered unsigned <code>.dsc</code> and every source file
 listed in <code>Checksums-Sha256</code>. The same digest re-uploaded with the
 same originals returns the existing archive; different originals are rejected
 with <code>409 Conflict</code>.</p>
<form method="post" action="/api/sources" enctype="multipart/form-data">
  <label>Binary .deb SHA-256<br>
  <input type="text" name="digest" size="68" pattern="[0-9a-f]{{64}}" required
         placeholder="64 hex characters"></label><br><br>
  <label>Unsigned .dsc<br>
  <input type="file" name="dsc" accept=".dsc" required></label><br><br>
  <label>Source files listed by Checksums-Sha256<br>
  <input type="file" name="files" multiple required></label><br>
  <button type="submit">Bind sources</button>
</form>

<h2>Client configuration</h2>
<pre>echo 'deb [trusted=yes arch={architecture}] {base_url} {suite} {component}' \\
  | sudo tee /etc/apt/sources.list.d/internal.list
sudo apt-get update
sudo apt-get download &lt;package&gt;</pre>
</body></html>
"""


def _media_type(relpath: str) -> str:
    name = relpath.rsplit("/", 1)[-1]
    return _MEDIA_TYPES.get(name, "application/octet-stream")


_STREAM_CHUNK = 256 * 1024


async def _stream(lease) -> AsyncIterator[bytes]:  # type: ignore[no-untyped-def]
    """Yield the leased file in chunks without blocking the event loop."""

    while True:
        chunk = await anyio.to_thread.run_sync(lease.fh.read, _STREAM_CHUNK)
        if not chunk:
            return
        yield chunk


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    repository = Repository(settings)
    source_store = SourceStore(settings, repository)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Recover from an interrupted publication/source write before serving.
        repository.reconcile()
        source_store.reconcile()
        yield

    app = FastAPI(
        title="Internal APT repository",
        version="1.1.0",
        description=(
            "Single-suite, single-component APT repository with atomic "
            "publications, Acquire-By-Hash retention of the last two "
            "successful releases and durable source-package bindings "
            "addressed by the binary package SHA-256."
        ),
        lifespan=lifespan,
        # /docs is the upload form; the generated OpenAPI UI lives at /swagger.
        docs_url=None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url="/swagger/oauth2-redirect",
    )
    app.state.settings = settings
    app.state.repository = repository
    app.state.source_store = source_store

    @app.exception_handler(DscError)
    async def dsc_error_handler(request: Request, exc: DscError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(BindingConflict)
    async def binding_conflict_handler(
        request: Request, exc: BindingConflict
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.get("/", response_class=PlainTextResponse)
    def root() -> str:
        return (
            "Internal APT repository\n"
            "=======================\n\n"
            f"Suite:        {settings.distribution}\n"
            f"Component:    {settings.component}\n"
            f"Architecture: {settings.architecture}\n\n"
            "Client configuration:\n"
            f"  {settings.sources_line}\n\n"
            "Then run: apt-get update && apt-get download <package>\n\n"
            "Upload packages at /docs or POST them to /api/publish.\n"
            "Bind builder sources to a .deb hash at /docs or POST to /api/sources;\n"
            "download the archive again at /api/sources/<sha256>.\n"
        )

    @app.get("/docs", response_class=HTMLResponse, include_in_schema=False)
    def upload_docs(request: Request) -> HTMLResponse:
        base_url = str(request.base_url).rstrip("/")
        return HTMLResponse(
            UPLOAD_FORM.format(
                suite=settings.distribution,
                component=settings.component,
                architecture=settings.architecture,
                base_url=base_url,
            )
        )

    @app.get("/swagger", include_in_schema=False)
    def swagger_redirect(request: Request) -> Response:
        return RedirectResponse(url=str(request.url_for("swagger_ui_html")))

    @app.get("/swagger-ui", response_class=HTMLResponse, include_in_schema=False)
    def swagger_ui_html(request: Request) -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url=app.openapi_url or "/openapi.json",
            title=f"{app.title} - OpenAPI",
            oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        )

    @app.post("/api/publish", response_model=None)
    def publish(files: list[UploadFile]) -> Response:
        if not files:
            raise HTTPException(status_code=400, detail="no files were uploaded")
        if len(files) > settings.max_batch_files:
            raise HTTPException(
                status_code=413,
                detail=f"at most {settings.max_batch_files} packages per publication",
            )

        token = uuid.uuid4().hex
        intake = repository.incoming / token
        intake.mkdir(parents=True, exist_ok=False)
        staged: list[StagedUpload] = []
        total = 0
        try:
            for index, upload in enumerate(files):
                name = Path(upload.filename or f"upload-{index}.deb").name
                if not name.endswith(".deb"):
                    raise HTTPException(
                        status_code=400,
                        detail=f"{name}: only .deb files are accepted",
                    )
                target = intake / f"{index:04d}.deb"
                size = 0
                with target.open("wb") as out:
                    while chunk := upload.file.read(1024 * 1024):
                        size += len(chunk)
                        total += len(chunk)
                        if size > settings.max_file_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail=f"{name}: package exceeds the size limit",
                            )
                        if total > settings.max_batch_bytes:
                            raise HTTPException(
                                status_code=413,
                                detail="uploaded batch exceeds the size limit",
                            )
                        out.write(chunk)
                    out.flush()
                if size == 0:
                    raise HTTPException(
                        status_code=400, detail=f"{name}: uploaded file is empty"
                    )
                staged.append(StagedUpload(path=target, original_name=name))

            try:
                publication = repository.publish(staged)
            except PublicationError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            shutil.rmtree(intake, ignore_errors=True)

        return JSONResponse(
            status_code=201,
            content={
                "published": publication.to_dict(),
                "release_url": f"/{settings.release_path}",
            },
        )

    @app.get("/api/status")
    def status() -> JSONResponse:
        body = repository.status()
        body["source_bindings"] = len(source_store.list_bindings(10000))
        return JSONResponse(body)

    @app.get("/api/publications")
    def publications() -> JSONResponse:
        return JSONResponse(
            {"publications": [p.to_dict() for p in repository.list_publications(50)]}
        )

    # ----------------------------------------------------------- source bindings
    @app.post("/api/sources", response_model=None)
    def bind_sources(
        digest: Annotated[str, Form()],
        dsc: UploadFile,
        files: list[UploadFile],
    ) -> Response:
        digest = (digest or "").strip().lower()
        if not is_digest(digest):
            raise HTTPException(
                status_code=400,
                detail="digest must be the 64 hex characters of a SHA-256",
            )
        if not dsc or not dsc.filename:
            raise HTTPException(status_code=400, detail="an unsigned .dsc is required")
        dsc_name = safe_basename(dsc.filename)
        if not dsc_name.endswith(".dsc"):
            raise HTTPException(
                status_code=400, detail=f"{dsc_name}: only .dsc files are accepted"
            )
        if not files:
            raise HTTPException(
                status_code=400,
                detail="at least one source file listed by Checksums-Sha256 is required",
            )

        token = uuid.uuid4().hex
        intake = repository.incoming / f"src-{token}"
        intake.mkdir(parents=True, exist_ok=False)
        try:
            dsc_bytes = b""
            with (intake / "0000.dsc").open("wb") as out:
                while chunk := dsc.file.read(1024 * 1024):
                    dsc_bytes += chunk
                    if len(dsc_bytes) > settings.max_file_bytes:
                        raise HTTPException(
                            status_code=413, detail=f"{dsc_name}: .dsc exceeds the size limit"
                        )
                    out.write(chunk)
            if not dsc_bytes:
                raise HTTPException(status_code=400, detail=f"{dsc_name}: uploaded file is empty")

            source_files: dict[str, bytes] = {}
            total = 0
            for index, upload in enumerate(files):
                name = safe_basename(upload.filename or f"source-{index}")
                if name in source_files or name == dsc_name:
                    raise HTTPException(
                        status_code=400, detail=f"duplicate upload file name: {name}"
                    )
                data = b""
                target = intake / f"{index:04d}.src"
                with target.open("wb") as out:
                    while chunk := upload.file.read(1024 * 1024):
                        data += chunk
                        total += len(chunk)
                        if len(data) > settings.max_file_bytes:
                            raise HTTPException(
                                status_code=413, detail=f"{name}: file exceeds the size limit"
                            )
                        if total > settings.max_batch_bytes:
                            raise HTTPException(
                                status_code=413, detail="uploaded batch exceeds the size limit"
                            )
                        out.write(chunk)
                if not data:
                    raise HTTPException(
                        status_code=400, detail=f"{name}: uploaded file is empty"
                    )
                source_files[name] = data

            try:
                binding = source_store.bind(digest, dsc_name, dsc_bytes, source_files)
            except BindingConflict as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            except DscError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except OSError as exc:
                raise HTTPException(
                    status_code=500, detail=f"could not write the source archive: {exc}"
                ) from exc
        finally:
            shutil.rmtree(intake, ignore_errors=True)

        return JSONResponse(status_code=201, content={"binding": binding.to_dict()})

    @app.get("/api/sources")
    def list_sources() -> JSONResponse:
        return JSONResponse(
            {"bindings": [binding.to_dict() for binding in source_store.list_bindings()]}
        )

    @app.get("/api/sources/{digest}")
    def download_source(digest: str) -> Response:
        digest = (digest or "").strip().lower()
        if not is_digest(digest):
            raise HTTPException(status_code=400, detail="invalid SHA-256 digest")
        lease = source_store.open_archive(digest)
        if lease is None:
            raise HTTPException(status_code=404, detail="no source binding for this digest")
        filename = f"{digest}.tar"
        headers = _lease_headers(lease)
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return StreamingResponse(
            _stream(lease),
            media_type="application/x-tar",
            headers=headers,
            background=BackgroundTask(lease.close),
        )

    @app.head("/api/sources/{digest}", include_in_schema=False)
    def download_source_head(digest: str) -> Response:
        digest = (digest or "").strip().lower()
        if not is_digest(digest):
            raise HTTPException(status_code=400, detail="invalid SHA-256 digest")
        lease = source_store.open_archive(digest)
        if lease is None:
            raise HTTPException(status_code=404, detail="no source binding for this digest")
        headers = _lease_headers(lease)
        headers["Content-Disposition"] = f'attachment; filename="{digest}.tar"'
        lease.close()
        return Response(status_code=200, media_type="application/x-tar", headers=headers)

    def _lease_headers(lease) -> dict[str, str]:  # type: ignore[no-untyped-def]
        return {
            "Cache-Control": "public, max-age=300",
            "Content-Length": str(lease.size),
            "ETag": lease.etag,
            "Last-Modified": formatdate(lease.last_modified, usegmt=True),
        }

    @app.get("/{relpath:path}", include_in_schema=False)
    def serve(relpath: str) -> Response:
        lease = repository.open_file(relpath)
        if lease is None:
            raise HTTPException(status_code=404, detail="not found")
        # Stream through the already-open descriptor: garbage collection may
        # unlink the name concurrently, but the inode stays readable.
        return StreamingResponse(
            _stream(lease),
            media_type=_media_type(relpath),
            headers=_lease_headers(lease),
            background=BackgroundTask(lease.close),
        )

    @app.head("/{relpath:path}", include_in_schema=False)
    def serve_head(relpath: str) -> Response:
        # FastAPI's router does not route HEAD to a GET catch-all path
        # operation, so HEAD is registered explicitly.
        lease = repository.open_file(relpath)
        if lease is None:
            raise HTTPException(status_code=404, detail="not found")
        headers = _lease_headers(lease)
        lease.close()
        return Response(status_code=200, media_type=_media_type(relpath), headers=headers)

    return app


app = create_app()
