"""Native PE fixtures and bounded IO contracts; no external analysis tools needed."""

import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from hypothesis import example, given, settings, strategies as st
import pytest

from bear import analysis
from bear.models import StringsRequest, TriageRequest


def synthetic_pe() -> bytearray:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 1234, 0, 0, 240, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", data, optional + 68, 3, 0x4140)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112 + 2 * 8, 0x2000, 0x400)
    for index, (name, rva, size, offset, flags) in enumerate([
        (b".text", 0x1000, 0x200, 0x200, 0x60000020),
        (b".rsrc", 0x2000, 0x400, 0x400, 0x40000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", data, 0x188 + index * 40,
                         name, size, rva, size, offset, 0, 0, 0, 0, flags)
    text = b"native code string\0"
    data[0x200:0x200 + len(text)] = text
    for relative, count in [(0, 1), (0x18, 1), (0x30, 2)]:
        struct.pack_into("<IIHHHH", data, 0x400 + relative, 0, 0, 0, 0, 0, count)
    for relative, key, target in [(0x10, 10, 0x80000018), (0x28, 7, 0x80000030),
                                  (0x40, 1033, 0x50), (0x48, 1041, 0x60)]:
        struct.pack_into("<II", data, 0x400 + relative, key, target)
    for leaf, offset, payload in [(0x50, 0x100, b"english resource\0"),
                                  (0x60, 0x140, b"\xff\x00japanese resource\0")]:
        struct.pack_into("<IIII", data, 0x400 + leaf, 0x2000 + offset, len(payload), 0, 0)
        data[0x400 + offset:0x400 + offset + len(payload)] = payload
    return data


@pytest.fixture
def pe_path(tmp_path):
    path = tmp_path / "fixture.exe"
    path.write_bytes(synthetic_pe())
    return path


@pytest.mark.parametrize("magic,expected", [
    (b"\x7fELF", "ELF"), (b"\xcf\xfa\xed\xfe", "MachO"),
    (b"\xca\xfe\xba\xbe", "MachO"), (b"MZ", "unknown"), (b"", "unknown"),
])
def test_header_detection(tmp_path, magic, expected):
    path = tmp_path / "header"
    path.write_bytes(magic)
    assert analysis.detect_format(path) == expected


def test_pe_metadata_is_native_and_fast_loaded(pe_path):
    with patch.object(analysis.pefile.PE, "full_load", side_effect=AssertionError("full PE load")):
        result = analysis.pe_metadata(pe_path)
    assert analysis.detect_format(pe_path) == "PE"
    assert result["bits"] == 64
    assert result["machine"] == 0x8664
    assert result["security"]["aslr"] is True
    assert result["security"]["nx_compat"] is True
    assert result["security"]["guard_cf"] is True
    assert result["security"]["signature_verified"] is None
    assert result["security"]["stack_cookie"] is None


def test_pe_triage_never_runs_elf_tools(pe_path):
    execute = Mock(side_effect=AssertionError("external command"))
    result = analysis.triage(TriageRequest(binary=str(pe_path)).model_dump(), execute)
    assert result["success"] is True
    assert result["checks"]["elf_header"]["status"] == "skipped"
    assert result["checks"]["dynamic_symbols"]["status"] == "skipped"
    assert result["checks"]["sha256"]["status"] == "skipped"
    assert result["summary"]["sha256"] is None
    execute.assert_not_called()


def test_triage_reports_real_tool_failure(tmp_path):
    path = tmp_path / "fake.elf"
    path.write_bytes(b"\x7fELF")
    result = analysis.triage({"binary": str(path), "strings_limit": 0},
                             Mock(return_value={"success": False, "stderr": "bad ELF"}))
    assert result["success"] is False


def test_hash_requires_separate_opt_in(pe_path):
    result = analysis.triage({"binary": str(pe_path), "compute_hash": True, "strings_limit": 0}, Mock())
    assert result["summary"]["sha256"] == hashlib.sha256(pe_path.read_bytes()).hexdigest()
    result = analysis.triage({"binary": str(pe_path), "full_scan": True, "strings_limit": 0}, Mock())
    assert result["checks"]["sha256"]["status"] == "skipped"


def test_pe_strings_exclude_resources_and_respect_window(pe_path):
    result = analysis.scan_strings(pe_path)
    assert "native code string" in result["stdout"]
    assert "resource" not in result["stdout"]
    assert result["scan"]["bytes_scanned"] == 0x200
    result = analysis.scan_strings(pe_path, include_resources=True)
    assert "english resource" in result["stdout"]
    result = analysis.scan_strings(pe_path, offset=0x500, length=7, include_resources=True)
    assert result["stdout"] == "english"
    assert result["strings"][0]["offset"] == 0x500
    assert analysis.scan_strings(pe_path, offset=0x500, length=7)["strings"] == []


def test_renamed_resource_section_is_still_excluded(pe_path):
    data = synthetic_pe()
    data[0x1B0:0x1B8] = b".data\0\0\0"
    pe_path.write_bytes(data)
    assert "resource" not in analysis.scan_strings(pe_path)["stdout"]


@pytest.mark.parametrize("format_name", ["unknown", "ELF", "PE"])
def test_sparse_gigabyte_triage_stays_bounded(tmp_path, format_name):
    path = tmp_path / "sparse"
    with path.open("wb") as source:
        source.write(synthetic_pe() if format_name == "PE" else b"\x7fELF" if format_name == "ELF" else b"\0")
        source.truncate(1024 * 1024 * 1024)
    with patch.object(analysis.hashlib, "sha256", side_effect=AssertionError("whole file hash")):
        result = analysis.triage(TriageRequest(binary=str(path)).model_dump(), Mock(side_effect=AssertionError("external scan")))
    assert result["success"] is True
    assert result["checks"]["strings"]["scan"]["bytes_scanned"] <= analysis.SCAN_LIMIT
    assert result["checks"]["strings"]["scan"]["skipped_bytes"] >= path.stat().st_size - analysis.SCAN_LIMIT


def test_full_scan_warns_and_scans_past_default_budget(tmp_path):
    path = tmp_path / "strings"
    path.write_bytes(b"\0" * 64 + b"late string")
    assert not analysis.scan_strings(path, max_scan_bytes=16)["strings"]
    result = analysis.scan_strings(path, max_scan_bytes=16, full_scan=True)
    assert result["stdout"] == "late string"
    assert any("full_scan" in warning for warning in result["warnings"])


@settings(database=None)
@given(data=st.binary() | st.text(alphabet="abc def\0").map(str.encode), window=st.data(),
       budget=st.integers(min_value=1, max_value=analysis.SCAN_LIMIT))
def test_scan_window_matches_independent_ascii_oracle(data, window, budget):
    offset = window.draw(st.integers(min_value=0) | st.integers(min_value=0, max_value=len(data)))
    length = window.draw(st.integers(min_value=0) | st.integers(min_value=0, max_value=len(data)))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input"
        path.write_bytes(data)
        result = analysis.scan_strings(path, offset=offset, length=length, max_scan_bytes=budget, full_scan=False)
    window = data[offset:offset + min(length, budget)]
    expected = [(offset + match.start(), match.group().decode("ascii"))
                for match in re.finditer(rb"[\x09\x20-\x7e]{4,}", window)]
    assert [(item["offset"], item["text"]) for item in result["strings"]] == expected
    assert result["scan"]["bytes_scanned"] <= min(length, budget, len(data))


@settings(database=None)
@given(text=st.text(alphabet="\t " + "abcdefghijklmnopqrstuvwxyz0123456789", min_size=4),
       chunk_size=st.integers(min_value=1, max_value=100),
       encoding=st.sampled_from(["s", "l", "b", "L", "B"]))
@example(text="abcdef", chunk_size=3, encoding="l")
def test_strings_are_independent_of_chunk_boundaries(text, chunk_size, encoding):
    codec = {"s": "ascii", "l": "utf-16-le", "b": "utf-16-be", "L": "utf-32-le", "B": "utf-32-be"}[encoding]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input"
        path.write_bytes(text.encode(codec))
        with patch.object(analysis, "CHUNK_SIZE", chunk_size):
            result = analysis.scan_strings(path, encoding=encoding)
    assert result["strings"] == [{"offset": 0, "text": text[:4096], "truncated": len(text) > 4096}]


@settings(database=None)
@given(data=st.binary() | st.text(alphabet="abc\0\t", min_size=0).map(lambda text: text.encode("utf-16-le")),
       chunk_size=st.integers(min_value=1, max_value=20),
       encoding=st.sampled_from(["s", "S", "l", "b", "L", "B"]))
def test_binary_strings_chunking_preserves_results(data, chunk_size, encoding):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input"
        path.write_bytes(data)
        expected = analysis.scan_strings(path, encoding=encoding, min_len=1)
        with patch.object(analysis, "CHUNK_SIZE", chunk_size):
            result = analysis.scan_strings(path, encoding=encoding, min_len=1)
    assert result["strings"] == expected["strings"]


def test_long_string_is_not_split_into_fake_strings(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"a" * (3 * analysis.CHUNK_SIZE) + b"\0second string")
    result = analysis.scan_strings(path)
    assert len(result["strings"]) == 2
    assert result["strings"][0] == {"offset": 0, "text": "a" * 4096, "truncated": True}
    assert result["strings"][1]["offset"] == 3 * analysis.CHUNK_SIZE + 1


def test_string_output_limits_and_unsupported_args(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"word\0" * 100)
    result = analysis.scan_strings(path, max_strings=2)
    assert len(result["strings"]) == 2
    assert result["scan"]["output_limited"] is True
    with pytest.raises(ValueError, match="additional_args"):
        analysis.scan_strings(path, additional_args="-a")


def test_resource_listing_pages_languages_without_reading_payloads(pe_path):
    with patch.object(analysis.pefile.PE, "parse_resources_directory", side_effect=AssertionError("eager resource parser")):
        result = analysis.list_resources(analysis.ResourcesRequest(binary=str(pe_path), resource_type=10, resource_id=7, limit=1))
    assert result["total"] == 2
    assert result["next_offset"] == 1
    assert result["resources"][0]["language"] == 1033
    result = analysis.list_resources(analysis.ResourcesRequest(binary=str(pe_path), offset=1))
    assert result["resources"][0]["language"] == 1041
    assert result["next_offset"] is None


def test_named_resource_identifiers(pe_path):
    data = synthetic_pe()
    struct.pack_into("<I", data, 0x428, 0x80000090)
    name = "named-id"
    struct.pack_into("<H", data, 0x490, len(name))
    data[0x492:0x492 + len(name) * 2] = name.encode("utf-16-le")
    pe_path.write_bytes(data)
    result = analysis.list_resources(analysis.ResourcesRequest(binary=str(pe_path), resource_id=name))
    assert result["total"] == 2
    assert result["resources"][0]["id"] == name


def test_extract_ambiguous_language_requires_selection(pe_path):
    with pytest.raises(HTTPException) as caught:
        analysis.extract_resource(analysis.ResourceExtractRequest(binary=str(pe_path), resource_id=7))
    assert caught.value.status_code == 409


def test_resource_extraction_streams_to_artifact_and_cleans_temp(pe_path):
    item = analysis.resource_catalog(str(pe_path))[1]
    paths = []

    def store(path):
        paths.append(path)
        assert path.read_bytes() == b"\xff\x00japanese resource\0"
        return {"artifact_id": "artifact", "size_bytes": path.stat().st_size}

    with patch.object(analysis, "CHUNK_SIZE", 3):
        result = analysis.process_resource(str(pe_path), item, "extract", 100, store)
    assert result["artifact"]["artifact_id"] == "artifact"
    assert not paths[0].exists()


def test_extract_by_artifact_id_uses_parent_storage_api(pe_path):
    artifact_path = Mock(return_value=pe_path)
    stored = []

    def store_file(path):
        stored.append(path.read_bytes())
        return {"artifact_id": "extracted", "size_bytes": path.stat().st_size}

    with patch.dict(sys.modules, {"bear.artifacts": SimpleNamespace(artifact_path=artifact_path, store_file=store_file)}):
        result = analysis.extract_resource(analysis.ResourceExtractRequest(artifact_id="source", resource_id=7, language=1033))
    artifact_path.assert_called_once_with("source")
    assert stored == [b"english resource\0"]
    assert result["artifact"]["artifact_id"] == "extracted"


@pytest.mark.parametrize("rva,size", [(0xFFFFFFF0, 64), (0x2400, 4), (0x2200, 0x800), (0x700, 4)])
def test_malformed_payload_rvas_are_listed_but_never_extracted(pe_path, rva, size):
    data = synthetic_pe()
    struct.pack_into("<II", data, 0x450, rva, size)
    pe_path.write_bytes(data)
    item = analysis.resource_catalog(str(pe_path))[0]
    assert item["valid"] is False
    store = Mock()
    with pytest.raises(ValueError, match="RVA"):
        analysis.process_resource(str(pe_path), item, "extract", analysis.MAX_RESOURCE_BYTES, store)
    store.assert_not_called()


@pytest.mark.parametrize("target", [0x80000000, 0x80000400, 0x7FFFFFFF])
def test_malformed_directory_rejected(pe_path, target):
    data = synthetic_pe()
    struct.pack_into("<I", data, 0x414, target)
    pe_path.write_bytes(data)
    with pytest.raises(ValueError):
        analysis.resource_catalog(str(pe_path))


def test_resource_and_header_metadata_limits(pe_path):
    with patch.object(analysis, "MAX_RESOURCE_ENTRIES", 2):
        with pytest.raises(ValueError, match="entry limit"):
            analysis.resource_catalog(str(pe_path))
    data = synthetic_pe()
    struct.pack_into("<I", data, 0x19C, 0x20000000)
    struct.pack_into("<I", data, 0x1C4, 0x30000000)
    pe_path.write_bytes(data)
    with pytest.raises(ValueError, match="padding"):
        analysis.pe_metadata(pe_path)


def test_resource_virtual_padding_is_not_file_backed(pe_path):
    data = synthetic_pe()
    struct.pack_into("<I", data, 0x1B8, 0x1000)
    struct.pack_into("<II", data, 0x450, 0x2500, 4)
    pe_path.write_bytes(data)
    assert analysis.resource_catalog(str(pe_path))[0]["valid"] is False


def test_large_sparse_resource_is_listed_without_reading_it(pe_path):
    size = 1024 * 1024 * 1024
    data = synthetic_pe()
    struct.pack_into("<I", data, 0x1B8, size - 0x400)
    struct.pack_into("<I", data, 0x1C0, size - 0x400)
    struct.pack_into("<I", data, 0x454, size - 0x500)
    with pe_path.open("wb") as source:
        source.write(data)
        source.truncate(size)
    item = analysis.resource_catalog(str(pe_path))[0]
    assert item["valid"] is True
    assert item["size_bytes"] == size - 0x500
    with pytest.raises(ValueError, match="max_bytes"):
        analysis.process_resource(str(pe_path), item, "extract", analysis.MAX_RESOURCE_BYTES, Mock())


def test_batch_hashes_once_parsed_directory_and_reports_real_progress(pe_path):
    updates = []
    store_bytes = Mock(return_value={"artifact_id": "manifest", "size_bytes": 1234})
    params = analysis.ResourceBatchRequest(binary=str(pe_path), operation="sha256", result_limit=1)
    with patch.object(analysis, "resource_catalog", wraps=analysis.resource_catalog) as catalog:
        result = analysis.run_resource_batch(params, update_progress=lambda **values: updates.append(values),
                                             check_cancelled=lambda: None, store_bytes=store_bytes)
    catalog.assert_called_once()
    assert result["completed_items"] == result["total_items"] == 2
    assert result["results"][0]["sha256"] == hashlib.sha256(b"english resource\0").hexdigest()
    assert result["next_result_offset"] == 1
    assert [update["completed_items"] for update in updates] == [0, 1, 2]
    assert updates[-1]["progress_percent"] == 100
    assert all(len(update["partial_results"]) <= 1 for update in updates)
    assert len(json.loads(store_bytes.call_args.args[0])) == 2
    assert result["results_artifact"]["artifact_id"] == "manifest"


def test_batch_byte_caps_report_failure_without_extracting(pe_path):
    store = Mock()
    result = analysis.run_resource_batch(
        analysis.ResourceBatchRequest(binary=str(pe_path), operation="extract", max_total_bytes=0),
        update_progress=lambda **values: None, check_cancelled=lambda: None, store_file=store)
    assert result["success"] is False
    assert result["failed_items"] == result["completed_items"] == 2
    store.assert_not_called()


def test_batch_item_selection_is_paged(pe_path):
    result = analysis.run_resource_batch(
        analysis.ResourceBatchRequest(binary=str(pe_path), operation="sha256", limit=1),
        update_progress=lambda **values: None, check_cancelled=lambda: None)
    assert result["total_items"] == result["completed_items"] == 1
    assert result["matched_total"] == 2
    assert result["next_offset"] == 1


def test_batch_cancellation_bounds_submissions_and_stops_workers(pe_path):
    worker_started = threading.Event()
    worker_stopped = threading.Event()
    task_thread = threading.get_ident()
    updates = []

    class TaskCancelled(Exception):
        pass

    def check():
        assert threading.get_ident() == task_thread
        if worker_started.is_set():
            raise TaskCancelled()

    def worker(path, item, operation, max_bytes, store_file, cancelled):
        worker_started.set()
        assert cancelled.wait(5)
        worker_stopped.set()
        raise analysis.CancelledError()

    params = analysis.ResourceBatchRequest(binary=str(pe_path), operation="sha256", concurrency=1)
    with patch.object(analysis, "process_resource", side_effect=worker) as process:
        with pytest.raises(TaskCancelled):
            analysis.run_resource_batch(params, update_progress=lambda **values: updates.append(values), check_cancelled=check)
    assert process.call_count == 1
    assert worker_stopped.is_set()
    assert updates[-1]["completed_items"] == 0


def test_router_models_and_listing(pe_path):
    app = FastAPI()
    app.include_router(analysis.router)
    with TestClient(app) as client:
        response = client.post("/api/tools/pe/resources", json={"binary": str(pe_path), "language": 1041})
        assert response.status_code == 200
        assert response.json()["total"] == 1
        assert client.post("/api/tools/pe/resources", json={"binary": str(pe_path), "limit": 201}).status_code == 422
        assert client.post("/api/tools/pe/resources", json={"binary": str(pe_path), "artifact_id": "both"}).status_code == 422


def test_server_pe_checksec_and_readelf_never_run_elf_commands(pe_path):
    from bear.server import app

    with TestClient(app) as client, patch("bear.server.execute_command", side_effect=AssertionError("ELF tool")):
        result = client.post("/api/tools/checksec", json={"binary": str(pe_path)})
        assert result.status_code == 200
        assert result.json()["format"] == "PE"
        result = client.post("/api/tools/readelf", json={"binary": str(pe_path)})
        assert result.json()["status"] == "skipped"


def test_batch_endpoint_returns_parent_submission_envelope(pe_path):
    submission = {"success": True, "async": True, "task_id": "test-task", "status": "queued"}
    with patch("bear.server.submit_task", return_value=submission, create=True) as submit, \
            patch("bear.server.update_task_progress", create=True), \
            patch("bear.server.check_task_cancelled", create=True):
        result = analysis.batch_resources(analysis.ResourceBatchRequest(binary=str(pe_path), operation="sha256"))
    assert result == submission
    assert callable(submit.call_args.args[0])


def test_request_defaults_are_bounded():
    assert StringsRequest(file_path="path").max_scan_bytes == analysis.SCAN_LIMIT
    assert TriageRequest(binary="path").compute_hash is False
    with pytest.raises(ValueError):
        analysis.ResourceBatchRequest(binary="path", operation="extract", concurrency=5)
    with pytest.raises(ValueError):
        analysis.ResourceBatchRequest(binary="path", operation="extract", limit=501)


def wait_for_resource_task(client, task_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(f"/api/tasks/{task_id}")
        assert response.status_code == 200, response.text
        task = response.json()
        if task["status"] in ("completed", "failed", "cancelled"):
            return task
        time.sleep(0.01)
    pytest.fail(f"Resource task did not finish: {task}")


@pytest.fixture
def resource_api(tmp_path, monkeypatch):
    from bear import server

    monkeypatch.setenv("BEAR_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.delenv("BEAR_MAX_ARTIFACT_BYTES", raising=False)
    with server.task_lock:
        previous_executor = server.task_executor
    task_ids = []
    # Do not enter the global lifespan: its shutdown cancels unrelated tasks.
    client = TestClient(server.app)
    try:
        yield client, task_ids
    finally:
        try:
            for task_id in task_ids:
                response = client.get(f"/api/tasks/{task_id}")
                if response.status_code == 200 and response.json()["status"] in ("queued", "running"):
                    client.delete(f"/api/tasks/{task_id}")
                wait_for_resource_task(client, task_id)
        finally:
            executor = None
            with server.task_lock:
                active = any(info["status"] in ("queued", "running") for info in server.task_results.values())
                if task_ids and previous_executor is None and not active:
                    executor, server.task_executor = server.task_executor, None
            if executor is not None:
                executor.shutdown(wait=True)
            with server.task_lock:
                for task_id in task_ids:
                    info = server.task_results.get(task_id)
                    if info is not None and info["status"] not in ("queued", "running"):
                        del server.task_results[task_id]
            client.close()


def read_resource_artifact(client, metadata, limit):
    restored = bytearray()
    while True:
        response = client.get(f"/api/artifacts/{metadata['artifact_id']}",
                              params={"offset": len(restored), "limit": limit})
        assert response.status_code == 200, response.text
        page = response.json()
        chunk = base64.b64decode(page["data"], validate=True)
        assert page["encoding"] == "base64"
        assert page["artifact_id"] == metadata["artifact_id"]
        assert page["size_bytes"] == metadata["size_bytes"]
        assert page["offset"] == len(restored)
        assert len(chunk) <= limit
        assert page["next_offset"] == len(restored) + len(chunk)
        restored.extend(chunk)
        if page["eof"]:
            assert len(restored) == metadata["size_bytes"]
            return bytes(restored)
        assert chunk, "Artifact page did not advance"


def test_resource_api_list_extract_artifact_roundtrip(resource_api, pe_path, tmp_path):
    from bear import artifacts

    client, _ = resource_api
    source = artifacts.store_file(pe_path)
    first = client.post("/api/tools/pe/resources", json={"binary": str(pe_path), "limit": 1})
    assert first.status_code == 200, first.text
    assert first.json()["total"] == 2
    assert first.json()["next_offset"] == 1
    assert len(first.json()["resources"]) == 1
    assert first.json()["resources"][0]["language"] == 1033

    pe_path.unlink()
    selection = {"artifact_id": source["artifact_id"], "resource_type": 10, "resource_id": 7}
    second = client.post("/api/tools/pe/resources", json={**selection, "offset": 1, "limit": 1})
    assert second.status_code == 200, second.text
    assert second.json()["total"] == 2
    assert second.json()["next_offset"] is None
    assert len(second.json()["resources"]) == 1
    assert second.json()["resources"][0]["language"] == 1041

    ambiguous = client.post("/api/tools/pe/resources/extract", json=selection)
    assert ambiguous.status_code == 409
    extracted = client.post("/api/tools/pe/resources/extract", json={**selection, "language": 1041})
    assert extracted.status_code == 200, extracted.text
    result = extracted.json()
    assert result["success"] is True
    assert result["resource"] == second.json()["resources"][0]
    assert artifacts.artifact_path(result["artifact"]["artifact_id"]).parent == tmp_path / "artifacts"
    assert read_resource_artifact(client, result["artifact"], limit=5) == b"\xff\x00japanese resource\0"


@pytest.mark.parametrize("result_offset", [0, 1])
def test_resource_batch_api_hashes_live_progress_and_bounded_pages(resource_api, pe_path, monkeypatch, result_offset):
    from bear import artifacts

    client, task_ids = resource_api
    source = artifacts.store_file(pe_path)
    pe_path.unlink()
    second_started = threading.Event()
    release_second = threading.Event()
    process_resource = analysis.process_resource

    def gated_resource(path, item, operation, max_bytes, store_file, cancelled):
        if item["language"] == 1041:
            second_started.set()
            assert release_second.wait(5), "Test did not release the second resource"
        return process_resource(path, item, operation, max_bytes, store_file, cancelled)

    monkeypatch.setattr(analysis, "process_resource", gated_resource)
    try:
        response = client.post("/api/tools/pe/resources/batch", json={
            "artifact_id": source["artifact_id"], "operation": "sha256",
            "resource_type": 10, "resource_id": 7, "concurrency": 1,
            "result_offset": result_offset, "result_limit": 1,
        })
        assert response.status_code == 200, response.text
        submission = response.json()
        task_ids.append(submission["task_id"])
        assert submission["success"] is True
        assert submission["async"] is True
        assert submission["status"] == "queued"
        assert second_started.wait(5), "Batch did not reach the second resource"

        response = client.get(f"/api/tasks/{submission['task_id']}")
        assert response.status_code == 200, response.text
        progress = response.json()
        assert progress["status"] == "running"
        assert progress["completed_items"] == 1
        assert progress["total_items"] == 2
        assert progress["progress_percent"] == 50
        assert "result" not in progress
        if result_offset == 0:
            assert len(progress["partial_results"]) == 1
            assert progress["partial_results"][0]["resource"]["language"] == 1033
            assert progress["partial_results"][0]["sha256"] == hashlib.sha256(b"english resource\0").hexdigest()
        else:
            assert progress["partial_results"] == []
    finally:
        release_second.set()

    task = wait_for_resource_task(client, submission["task_id"])
    assert task["status"] == "completed", task
    assert task["completed_items"] == task["total_items"] == 2
    assert task["progress_percent"] == 100
    result = task["result"]
    assert result["success"] is True
    assert result["failed_items"] == 0
    assert result["completed_items"] == result["total_items"] == 2
    assert result["matched_total"] == 2
    assert result["next_offset"] is None
    assert len(result["results"]) == 1
    assert result["result_offset"] == result_offset
    assert result["next_result_offset"] == (1 if result_offset == 0 else None)
    assert task["partial_results"] == result["results"]

    manifest = json.loads(read_resource_artifact(client, result["results_artifact"], limit=97))
    assert len(manifest) == 2
    assert result["results"] == manifest[result_offset:result_offset + 1]
    assert all(item["success"] for item in manifest)
    assert {item["resource"]["language"]: item["sha256"] for item in manifest} == {
        1033: hashlib.sha256(b"english resource\0").hexdigest(),
        1041: hashlib.sha256(b"\xff\x00japanese resource\0").hexdigest(),
    }


@settings(max_examples=50, deadline=None, database=None)
@given(offset=st.sampled_from([
    0x3C, 0x84, 0x94, 0x98, 0xB8, 0xBC, 0xD4, 0x104, 0x118, 0x11C,
    0x190, 0x194, 0x198, 0x19C, 0x1B8, 0x1BC, 0x1C0, 0x1C4,
    0x40C, 0x410, 0x414, 0x450, 0x454,
]), value=st.integers(min_value=0, max_value=0xFFFFFFFF))
@example(offset=0xBC, value=0)
@example(offset=0x118, value=0xFFFFFFFF)
@example(offset=0x450, value=0xFFFFFFFF)
def test_mutated_pe_resource_metadata_has_no_unhandled_errors(offset, value):
    data = synthetic_pe()
    struct.pack_into("<I", data, offset, value)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "mutated.exe"
        path.write_bytes(data)
        try:
            resources = analysis.resource_catalog(str(path))
        except ValueError:
            return
    for item in resources:
        if item["valid"]:
            assert 0 <= item["offset"] <= len(data)
            assert item["offset"] + item["size_bytes"] <= len(data)
