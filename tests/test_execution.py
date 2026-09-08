"""Real subprocess capture, process-group cleanup, and artifact contracts."""

import base64
import json
import re
import subprocess
import sys
import threading
import time
from unittest.mock import Mock

import psutil
import pytest
from hypothesis import example, given, settings, strategies as st

from bear import artifacts
from bear import server


class CancellationRequested(Exception):
    pass


@pytest.fixture(autouse=True)
def isolated_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("BEAR_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.delenv("BEAR_MAX_ARTIFACT_BYTES", raising=False)
    monkeypatch.delenv("BEAR_MAX_OUTPUT_BYTES", raising=False)
    # The task runner owns these hooks. Exercise their contract without a server.
    monkeypatch.setattr(server, "TaskCancelled", CancellationRequested, raising=False)
    monkeypatch.setattr(server, "task_context", threading.local(), raising=False)
    monkeypatch.setattr(server, "check_task_cancelled", lambda: None, raising=False)
    monkeypatch.setattr(server, "update_task_progress", Mock(), raising=False)
    monkeypatch.setattr(server, "active_processes", {})
    monkeypatch.setattr(server, "telemetry", Mock())
    monkeypatch.setattr(server, "cache", Mock(get=Mock(return_value=None)))


def captured_bytes(result, stream):
    if f"{stream}_artifact" in result:
        metadata = result[f"{stream}_artifact"]
        data = artifacts.artifact_path(metadata["artifact_id"]).read_bytes()
        assert len(data) == metadata["size_bytes"]
        return data
    return result[stream].encode("utf-8")


def assert_not_running(pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            if psutil.Process(pid).status() == psutil.STATUS_ZOMBIE:
                return  # Only the orphan's new parent can reap it.
        except psutil.NoSuchProcess:
            return
        time.sleep(0.01)
    pytest.fail(f"Descendant {pid} survived process-group termination")


TREE_SCRIPT = """
import os, signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, '-u', '-c',
    'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
    'print("ready",flush=True); time.sleep(60)'], stdout=subprocess.PIPE)
assert child.stdout.readline() == b'ready\\n'
print(child.pid, flush=True)
"""


def test_long_single_lines_are_fully_drained_to_artifacts():
    executor = server.EnhancedCommandExecutor([
        sys.executable, "-c",
        "import os; os.write(1,b'A'*2000000); os.write(2,b'B'*1500000)",
    ], timeout=10)
    result = executor.execute()

    assert result["success"] is True
    assert captured_bytes(result, "stdout") == b"A" * 2_000_000
    assert captured_bytes(result, "stderr") == b"B" * 1_500_000
    assert result["output_bytes"] == 3_500_000
    assert len(result["stdout"]) <= artifacts.PREVIEW_BYTES
    assert len(result["stderr"]) <= artifacts.PREVIEW_BYTES
    assert executor.process.poll() == 0
    assert server.active_processes == {}


@settings(max_examples=25, deadline=None)
@given(stdout=st.binary(), stderr=st.binary())
@example(stdout=b"\xff\x00\xc3", stderr="\U0001f43b\u2603".encode("utf-8"))
@example(stdout=b"a" * (artifacts.PREVIEW_BYTES - 1) + "\U0001f43b".encode("utf-8"), stderr=b"\xff" * 5000)
def test_binary_output_roundtrip_and_preview_bounds(stdout, stderr):
    command = [sys.executable, "-c",
               "import base64,os,sys; os.write(1,base64.b64decode(sys.argv[1])); "
               "os.write(2,base64.b64decode(sys.argv[2]))",
               base64.b64encode(stdout).decode("ascii"), base64.b64encode(stderr).decode("ascii")]
    result = server.EnhancedCommandExecutor(command, timeout=10).execute()

    assert result["success"] is True
    assert captured_bytes(result, "stdout") == stdout
    assert captured_bytes(result, "stderr") == stderr
    assert result["output_bytes"] == len(stdout) + len(stderr)
    assert len(result["stdout"]) <= artifacts.PREVIEW_BYTES
    assert len(result["stderr"]) <= artifacts.PREVIEW_BYTES
    assert len(artifacts.BoundedJSONResponse(result).body) <= artifacts.MAX_INLINE_BYTES


def test_limit_is_shared_across_streams_and_kills_descendants():
    script = TREE_SCRIPT + "\nos.write(2, b'E'*16384)\nwhile True: os.write(1, b'O'*65536)\n"
    executor = server.EnhancedCommandExecutor([sys.executable, "-u", "-c", script],
                                              timeout=10, max_output_bytes=65536)
    result = executor.execute()

    assert result["success"] is False
    assert result["error"] == "output_limit_exceeded"
    assert result["output_limit_exceeded"] is True
    assert result["timed_out"] is False
    assert result["output_bytes"] == 65536
    assert len(captured_bytes(result, "stdout")) + len(captured_bytes(result, "stderr")) == 65536
    assert_not_running(int(result["stdout"].splitlines()[0]))
    assert executor.process.poll() is not None
    assert server.active_processes == {}


def test_exact_output_limit_is_not_an_error():
    result = server.EnhancedCommandExecutor(
        [sys.executable, "-c", "import os; os.write(1,b'x'*32768); os.write(2,b'y'*32768)"],
        max_output_bytes=65536,
    ).execute()
    assert result["success"] is True
    assert result["output_limit_exceeded"] is False
    assert result["output_bytes"] == 65536


@settings(max_examples=25, deadline=None)
@given(data=st.binary(), limit=st.integers(min_value=0))
@example(data=b"x" * 70000, limit=65536)
@example(data=b"\xff\x00", limit=1)
def test_combined_output_never_exceeds_configured_cap(data, limit):
    command = [sys.executable, "-c",
               "import base64,os,sys; data=base64.b64decode(sys.argv[1]); "
               "os.write(1,data[:len(data)//2]); os.write(2,data[len(data)//2:])",
               base64.b64encode(data).decode("ascii")]
    result = server.EnhancedCommandExecutor(command, max_output_bytes=limit).execute()
    assert result["output_bytes"] == min(len(data), limit)
    assert result["output_limit_exceeded"] == (len(data) > limit)
    assert result["success"] == (len(data) <= limit)
    assert len(captured_bytes(result, "stdout")) + len(captured_bytes(result, "stderr")) <= limit
    if len(data) > limit:
        assert result["error"] == "output_limit_exceeded"


def test_default_output_cap_and_environment_override(monkeypatch):
    assert server.EnhancedCommandExecutor("true").max_output_bytes == 256 * 1024 * 1024
    monkeypatch.setenv("BEAR_MAX_OUTPUT_BYTES", "12345")
    assert server.EnhancedCommandExecutor("true").max_output_bytes == 12345
    assert server.EnhancedCommandExecutor("true", max_output_bytes=100).max_output_bytes == 100


def test_zero_output_limit_accepts_silent_commands_and_rejects_output():
    silent = server.EnhancedCommandExecutor([sys.executable, "-c", "pass"], max_output_bytes=0).execute()
    noisy = server.EnhancedCommandExecutor([sys.executable, "-c", "print('x')"], max_output_bytes=0).execute()
    assert silent["success"] is True
    assert noisy["error"] == "output_limit_exceeded"
    assert noisy["stdout"] == ""
    assert noisy["output_bytes"] == 0


def test_timeout_kills_term_ignoring_descendants_and_reaps_leader():
    executor = server.EnhancedCommandExecutor(
        [sys.executable, "-u", "-c", TREE_SCRIPT + "time.sleep(60)"], timeout=0.5)
    result = executor.execute()

    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["return_code"] != 0
    assert_not_running(int(result["stdout"].strip()))
    assert executor.process.poll() is not None
    assert server.active_processes == {}


def test_timeout_cleans_group_after_leader_exits_with_inherited_pipes():
    script = (
        "import subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "print(child.pid,flush=True)"
    )
    executor = server.EnhancedCommandExecutor([sys.executable, "-c", script], timeout=0.5)
    result = executor.execute()
    assert result["timed_out"] is True
    assert result["success"] is False
    assert executor.process.returncode == 0
    assert_not_running(int(result["stdout"].strip()))
    assert server.active_processes == {}


@pytest.mark.parametrize("failure", ["timeout", "output_limit"])
def test_termination_does_not_wait_for_detached_child_pipe_eof(failure):
    script = (
        "import subprocess,sys; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(4)'],start_new_session=True); "
        "print(child.pid,flush=True); "
        + ("print('x'*65536,flush=True)" if failure == "output_limit" else "pass")
    )
    executor = server.EnhancedCommandExecutor([sys.executable, "-u", "-c", script],
                                              timeout=0.3 if failure == "timeout" else 10,
                                              max_output_bytes=64 if failure == "output_limit" else 65536)
    start = time.monotonic()
    result = executor.execute()
    elapsed = time.monotonic() - start
    child_pid = int(result["stdout"].splitlines()[0])
    try:
        assert elapsed < 2.5
        assert result["success"] is False
        assert result["timed_out"] == (failure == "timeout")
        assert result["output_limit_exceeded"] == (failure == "output_limit")
        assert result["output_incomplete"] is True
        assert result["stdout_truncated"] is True
        assert server.active_processes == {}
    finally:
        try:
            psutil.Process(child_pid).kill()
        except psutil.NoSuchProcess:
            pass
        assert_not_running(child_pid)


def test_cancellation_propagates_after_group_cleanup_with_live_progress(monkeypatch):
    server.task_context.task_id = "cancel-this-task"
    updates = []
    checks = []
    cancellation = threading.Event()
    timer = None

    def check_cancelled():
        checks.append(time.monotonic())
        if cancellation.is_set():
            raise CancellationRequested("cancelled")

    def update_progress(**fields):
        nonlocal timer
        updates.append(fields)
        assert fields["stage"] == "executing"
        assert fields["progress_percent"] is None
        if fields["output_bytes"] and timer is None:
            statuses = server.ProcessManager.list_active_processes()
            assert len(statuses) == 1
            status = next(iter(statuses.values()))
            assert status["task_id"] == "cancel-this-task"
            assert "process" not in status
            timer = threading.Timer(0.25, cancellation.set)
            timer.start()

    monkeypatch.setattr(server, "check_task_cancelled", check_cancelled)
    monkeypatch.setattr(server, "update_task_progress", update_progress)
    executor = server.EnhancedCommandExecutor(
        [sys.executable, "-u", "-c", TREE_SCRIPT + "time.sleep(60)"], timeout=5)
    try:
        with pytest.raises(CancellationRequested, match="cancelled"):
            executor.execute()
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()

    assert updates[0]["output_bytes"] == 0
    partial = next(fields for fields in updates if fields["output_bytes"])
    assert_not_running(int(partial["stdout_preview"].strip()))
    assert max(b - a for a, b in zip(checks, checks[1:])) < 0.3
    assert executor.process.poll() is not None
    assert server.active_processes == {}
    server.telemetry.record_execution.assert_called_once()
    assert server.telemetry.record_execution.call_args.args[0] is False


def test_cancel_before_spawn_does_not_start_a_process(monkeypatch):
    monkeypatch.setattr(server, "check_task_cancelled", Mock(side_effect=CancellationRequested))
    popen = Mock()
    monkeypatch.setattr(server.subprocess, "Popen", popen)
    with pytest.raises(CancellationRequested):
        server.EnhancedCommandExecutor([sys.executable, "-c", "pass"]).execute()
    popen.assert_not_called()
    assert server.active_processes == {}


def test_cancellation_during_artifact_copy_is_not_reported_as_success(monkeypatch):
    store_file = artifacts.store_file

    def store_and_cancel(path):
        metadata = store_file(path)
        monkeypatch.setattr(server, "check_task_cancelled", Mock(side_effect=CancellationRequested))
        return metadata

    monkeypatch.setattr(artifacts, "store_file", store_and_cancel)
    executor = server.EnhancedCommandExecutor([sys.executable, "-c", "print('x'*10000)"])
    with pytest.raises(CancellationRequested):
        executor.execute()
    assert executor.process.poll() is not None
    assert server.active_processes == {}


def test_shell_strings_and_argv_lists_keep_their_execution_modes():
    shell = server.execute_command("printf '%s' shell-output", use_cache=False)
    argv = server.execute_command([sys.executable, "-c", "import sys; print(sys.argv[1],end='')",
                                   "$(not-a-shell-command); literal"], use_cache=False)
    assert shell["stdout"] == "shell-output"
    assert argv["stdout"] == "$(not-a-shell-command); literal"


def test_cache_logs_outcomes_without_command_or_output_secrets(caplog):
    caplog.set_level("INFO", logger=server.__name__)
    command = [sys.executable, "-c", "print('secret-token-123')"]
    first = server.execute_command(command)
    server.cache.set.assert_called_once()
    server.cache.get.return_value = first
    assert server.execute_command(command) == first
    assert "cache=miss" in caplog.text
    assert "cache=hit" in caplog.text
    assert "return_code=0" in caplog.text
    assert "timed_out=False" in caplog.text
    assert "execution_time=" in caplog.text
    assert "secret-token-123" not in caplog.text


def test_output_limit_failures_are_not_cached():
    result = server.execute_command([sys.executable, "-c", "print('too much')"], max_output_bytes=1)
    assert result["error"] == "output_limit_exceeded"
    server.cache.set.assert_not_called()


def test_cache_keys_include_capture_version_and_limits():
    params = {"binary": "/tmp/example"}
    server.execute_command([sys.executable, "-c", "pass"], timeout=5,
                           cache_params=params, max_output_bytes=100)
    key_params = server.cache.get.call_args.args[1]
    assert key_params["_max_output_bytes"] == 100
    assert key_params["_timeout"] == 5
    assert key_params["_bounded_output_version"] == 1
    assert params == {"binary": "/tmp/example"}


@pytest.mark.parametrize("backend", ["objdump", "auto"])
def test_objdump_disassembly_cache_invalidates_changed_binary(tmp_path, monkeypatch, backend):
    from bear.ghidra import DisassembleRequest

    binary = tmp_path / "program"
    binary.write_bytes(b"first")
    cache = server.BearCache(directory=str(tmp_path / "cache"))
    monkeypatch.setattr(server, "cache", cache)
    monkeypatch.setattr(server, "find_ghidra_headless", lambda: None)
    execute = Mock(side_effect=lambda: {"success": True, "stdout": binary.read_text()})
    monkeypatch.setattr(server.EnhancedCommandExecutor, "execute", execute)
    params = DisassembleRequest(binary=str(binary), backend=backend)
    try:
        assert server.disassemble_binary(params)["stdout"] == "first"
        assert server.disassemble_binary(params)["stdout"] == "first"
        assert execute.call_count == 1
        binary.write_bytes(b"changed binary")
        assert server.disassemble_binary(params)["stdout"] == "changed binary"
        assert execute.call_count == 2
    finally:
        cache.cache.close()


def test_artifact_storage_failure_is_reported_and_registry_cleaned(monkeypatch):
    monkeypatch.setattr(artifacts, "store_file", Mock(side_effect=OSError("disk full")))
    executor = server.EnhancedCommandExecutor([sys.executable, "-c", "print('x'*10000)"])
    result = executor.execute()
    assert result["success"] is False
    assert "disk full" in result["error"]
    assert executor.process.poll() is not None
    assert server.active_processes == {}


def test_launch_failure_is_reported_without_registry_leak():
    result = server.EnhancedCommandExecutor(["/nonexistent/bear-test-executable"]).execute()
    assert result["success"] is False
    assert result["return_code"] == -1
    assert server.active_processes == {}


def test_process_manager_legacy_api_and_serializable_snapshots():
    process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True)
    server.task_context.task_id = "legacy-process-task"
    try:
        server.ProcessManager.register_process(process.pid, "sleep", process)
        server.ProcessManager.update_process_progress(process.pid, 0.5, "x" * 20000, 20000)
        status = server.ProcessManager.get_process_status(process.pid)
        assert {"pid", "command", "start_time", "status", "progress", "last_output",
                "bytes_processed", "runtime", "eta"} <= status.keys()
        assert status["task_id"] == "legacy-process-task"
        assert len(status["last_output"]) == 4096
        json.dumps(status)
        json.dumps(server.ProcessManager.list_active_processes())
        assert server.ProcessManager.pause_process(process.pid) is True
        assert server.ProcessManager.get_process_status(process.pid)["status"] == "paused"
        assert server.ProcessManager.resume_process(process.pid) is True
        assert server.ProcessManager.terminate_process(process.pid) is True
        assert process.poll() is not None
        assert server.ProcessManager.get_process_status(process.pid)["status"] == "terminated"
    finally:
        server.ProcessManager._terminate_process_group(process)
        server.ProcessManager.cleanup_process(process.pid)
    assert server.ProcessManager.get_process_status(process.pid) is None
    assert server.ProcessManager.terminate_process(process.pid) is False


@settings(deadline=None)
@given(data=st.binary(), page_size=st.integers(min_value=1))
@example(data=bytes(range(256)) * 1024, page_size=7919)
def test_artifact_paging_roundtrip_and_response_bounds(data, page_size):
    metadata = artifacts.store_bytes(data)
    assert metadata["size_bytes"] == len(data)
    assert re.fullmatch(r"[0-9a-f]{32}", metadata["artifact_id"])
    offset = 0
    restored = bytearray()
    while True:
        page = artifacts.read_artifact(metadata["artifact_id"], offset, page_size)
        decoded = base64.b64decode(page["data"], validate=True)
        assert len(decoded) <= min(page_size, artifacts.MAX_PAGE_BYTES)
        assert len(artifacts.BoundedJSONResponse(page).body) <= artifacts.MAX_INLINE_BYTES
        assert page["offset"] == offset
        assert page["next_offset"] == offset + len(decoded)
        assert page["size_bytes"] == len(data)
        restored.extend(decoded)
        if page["eof"]:
            break
        assert page["next_offset"] > offset
        offset = page["next_offset"]
    assert bytes(restored) == data


@given(data=st.binary(), offset=st.integers(min_value=0), limit=st.integers(min_value=1))
def test_artifact_random_access_matches_byte_slicing(data, offset, limit):
    metadata = artifacts.store_bytes(data)
    page = artifacts.read_artifact(metadata["artifact_id"], offset, limit)
    assert base64.b64decode(page["data"]) == data[offset:offset + min(limit, artifacts.MAX_PAGE_BYTES)]
    assert page["eof"] == (offset + min(limit, artifacts.MAX_PAGE_BYTES) >= len(data))


@given(identifier=st.text())
@example(identifier="../" + "a" * 32)
@example(identifier="a" * 32 + "\n")
def test_artifact_identifiers_cannot_escape_storage(identifier):
    if re.fullmatch(r"[0-9a-fA-F]{32}", identifier):
        assert artifacts.artifact_path(identifier).name == identifier.lower()
    else:
        with pytest.raises(ValueError):
            artifacts.artifact_path(identifier)


@pytest.mark.parametrize("offset,limit", [(-1, 1), (0, 0), (0, -1), (False, 1), (0, True)])
def test_artifact_page_arguments_are_validated(offset, limit):
    with pytest.raises(ValueError):
        artifacts.read_artifact("a" * 32, offset, limit)


def test_store_file_copies_synchronously_and_preserves_source(tmp_path):
    source = tmp_path / "source.bin"
    data = bytes(range(256)) * 1000
    source.write_bytes(data)
    metadata = artifacts.store_file(source)
    assert source.read_bytes() == data
    source.unlink()
    assert artifacts.artifact_path(metadata["artifact_id"]).read_bytes() == data


@pytest.mark.parametrize("use_file", [False, True])
def test_artifact_size_cap_cleans_incomplete_files(tmp_path, monkeypatch, use_file):
    monkeypatch.setenv("BEAR_MAX_ARTIFACT_BYTES", "70000")
    source = tmp_path / "source.bin"
    data = b"x" * 70001
    source.write_bytes(data)
    with pytest.raises(artifacts.ArtifactLimitExceeded, match="artifact_limit_exceeded"):
        artifacts.store_file(source) if use_file else artifacts.store_bytes(data)
    assert list((tmp_path / "artifacts").iterdir()) == []
    assert source.read_bytes() == data


def test_artifact_symlinks_are_rejected(tmp_path):
    metadata = artifacts.store_bytes(b"content")
    path = artifacts.artifact_path(metadata["artifact_id"])
    path.unlink()
    path.symlink_to(tmp_path / "unrelated")
    with pytest.raises(ValueError, match="symbolic links"):
        artifacts.artifact_path(metadata["artifact_id"])


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(alphabet=st.characters()),
    lambda children: st.lists(children) | st.dictionaries(st.text(alphabet=st.characters()), children),
)


@settings(deadline=None)
@given(value=st.dictionaries(st.text(alphabet=st.characters()), json_values) | st.lists(json_values))
@example(value={"success": False, "task_id": "abc", "status": "failed", "output": "\udcff" * 10000})
@example(value=["\U0001f43b" * 10000])
def test_bounded_json_roundtrip_is_lossless_within_response_budget(value):
    response = artifacts.BoundedJSONResponse(value)
    assert len(response.body) <= artifacts.MAX_INLINE_BYTES
    decoded = json.loads(response.body)
    if isinstance(decoded, dict) and decoded.get("truncated") and "artifact" in decoded:
        decoded = json.loads(artifacts.artifact_path(decoded["artifact"]["artifact_id"]).read_bytes())
    assert decoded == value


def test_large_result_envelope_preserves_task_identity_and_boolean_success():
    result = {"success": False, "task_id": "task-123", "status": "failed", "output": "x" * 50000}
    bounded = artifacts.bounded_result(result)
    assert bounded["success"] is False
    assert bounded["task_id"] == "task-123"
    assert bounded["status"] == "failed"
    assert bounded["truncated"] is True
    assert len(bounded["preview"]) <= 1000
    assert json.loads(artifacts.artifact_path(bounded["artifact"]["artifact_id"]).read_bytes()) == result


def test_small_surrogate_json_remains_inline_and_encodes_safely():
    result = {"output": "\udcff"}
    assert artifacts.bounded_result(result) is result
    assert json.loads(artifacts.BoundedJSONResponse(result).body) == result


def test_json_inline_budget_boundary():
    result = {"x": "x" * (artifacts.MAX_INLINE_BYTES - len(b'{"x":""}'))}
    assert artifacts.bounded_result(result) is result
    assert len(artifacts.BoundedJSONResponse(result).body) == artifacts.MAX_INLINE_BYTES
    result["x"] += "x"
    assert artifacts.bounded_result(result)["truncated"] is True


def test_oversized_task_fields_cannot_expand_the_envelope():
    result = {"success": "not-a-bool", "task_id": "x" * 50000, "status": ["x"] * 50000}
    bounded = artifacts.bounded_result(result)
    assert "success" not in bounded
    assert "task_id" not in bounded
    assert "status" not in bounded
    assert len(artifacts.BoundedJSONResponse(bounded).body) <= artifacts.MAX_INLINE_BYTES


def test_large_json_exceeding_artifact_limit_fails_instead_of_returning_a_partial_handle(monkeypatch):
    monkeypatch.setenv("BEAR_MAX_ARTIFACT_BYTES", "20000")
    with pytest.raises(artifacts.ArtifactLimitExceeded):
        artifacts.bounded_result({"output": "x" * 20000})
