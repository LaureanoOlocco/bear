"""Immutable, bounded local artifacts and small JSON response envelopes.

BEAR_ARTIFACT_DIR defaults to .bear_artifacts. Each artifact is limited by
BEAR_MAX_ARTIFACT_BYTES (256 MiB by default). Artifacts have no automatic TTL:
operators must remove them only after referencing tasks, cache entries, and
clients have finished with them, or clear it together with command/task caches
while BEAR is stopped.
There is deliberately no eviction that could invalidate an active handle.
"""

import base64
import itertools
import json
import os
import re
import tempfile
import uuid
from pathlib import Path

from fastapi.responses import JSONResponse


MAX_INLINE_BYTES = 16_000
MAX_PAGE_BYTES = 8192
PREVIEW_BYTES = 4096
DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024 * 1024
COPY_CHUNK_BYTES = 64 * 1024


class ArtifactLimitExceeded(ValueError):
    """The complete artifact cannot be stored within the configured limit."""


def artifact_path(artifact_id: str) -> Path:
    """Resolve only a UUID's 32 hexadecimal digits, never an arbitrary path."""
    if not isinstance(artifact_id, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", artifact_id):
        raise ValueError("artifact_id must contain exactly 32 hexadecimal digits")
    path = Path(os.environ.get("BEAR_ARTIFACT_DIR", ".bear_artifacts")) / artifact_id.lower()
    if path.is_symlink():
        raise ValueError("Artifact paths must not be symbolic links")
    return path


def _store_chunks(chunks) -> dict:
    max_bytes = int(os.environ.get("BEAR_MAX_ARTIFACT_BYTES", DEFAULT_MAX_OUTPUT_BYTES))
    if max_bytes < 0:
        raise ValueError("BEAR_MAX_ARTIFACT_BYTES must be nonnegative")
    artifact_id = uuid.uuid4().hex
    destination = artifact_path(artifact_id)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    size = 0
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".pending-", delete=False) as output:
            temporary = Path(output.name)
            for chunk in chunks:
                size += len(chunk)
                if size > max_bytes:
                    raise ArtifactLimitExceeded("artifact_limit_exceeded")
                output.write(chunk)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"artifact_id": artifact_id, "size_bytes": size}


def store_bytes(data: bytes) -> dict:
    """Synchronously persist exact bytes, publishing only a complete artifact."""
    return _store_chunks(memoryview(data)[offset:offset + COPY_CHUNK_BYTES]
                         for offset in range(0, len(data), COPY_CHUNK_BYTES))


def store_file(path: str | Path) -> dict:
    """Synchronously copy a file in bounded chunks; leave its source untouched."""
    with open(path, "rb") as source:
        return _store_chunks(iter(lambda: source.read(COPY_CHUNK_BYTES), b""))


def read_artifact(artifact_id: str, offset: int = 0, limit: int = MAX_PAGE_BYTES) -> dict:
    """Return a lossless base64 page of at most 8192 bytes, with byte offsets."""
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a nonnegative integer")
    if type(limit) is not int or limit <= 0:
        raise ValueError("limit must be a positive integer")
    with artifact_path(artifact_id).open("rb") as source:
        size = os.fstat(source.fileno()).st_size
        offset = min(offset, size)
        source.seek(offset)
        data = source.read(min(limit, MAX_PAGE_BYTES))
    next_offset = offset + len(data)
    return {
        "artifact_id": artifact_id.lower(),
        "encoding": "base64",
        "data": base64.b64encode(data).decode("ascii"),
        "offset": offset,
        "next_offset": next_offset,
        "eof": next_offset >= size,
        "size_bytes": size,
    }


def bounded_result(result: dict | list) -> dict | list:
    """Keep small JSON inline, otherwise persist it and return a small envelope.

    The 16 KB budget leaves room for transports that duplicate JSON as both
    text and structured content. JSON uses ASCII escapes, including surrogates.
    """
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    chunks = (part.encode("ascii") for part in encoder.iterencode(result))
    inline = bytearray()
    for chunk in chunks:
        if len(inline) + len(chunk) <= MAX_INLINE_BYTES:
            inline.extend(chunk)
            continue
        preview = (bytes(inline[:1000]) + chunk[:max(0, 1000 - len(inline))]).decode("ascii")
        artifact = _store_chunks(itertools.chain((bytes(inline), chunk), chunks))
        envelope = {"truncated": True, "artifact": artifact, "preview": preview}
        if isinstance(result, dict):
            if isinstance(result.get("success"), bool):
                envelope["success"] = result["success"]
            for field in ("task_id", "status"):
                if field in result and type(result[field]) in (str, int, float, bool, type(None)):
                    # Do not shorten identifiers into misleading, unusable handles.
                    if len(encoder.encode(result[field])) <= 1024:
                        envelope[field] = result[field]
        return envelope
    return result


class BoundedJSONResponse(JSONResponse):
    """FastAPI default response class; raw artifact downloads use Response."""

    def render(self, content) -> bytes:
        if isinstance(content, (dict, list)):
            content = bounded_result(content)
        return json.dumps(content, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")
