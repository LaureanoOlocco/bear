"""MCP registration, transport safety, and API wrapper contracts."""

import asyncio
from contextlib import ExitStack
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, call

import anyio
import pytest
import requests
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StdioTransport
from urllib3.exceptions import MaxRetryError, NewConnectionError, ProtocolError, ReadTimeoutError

from bear import mcp as bear_mcp
from bear.models import StringsRequest, TriageRequest


def response(payload=None, status=200):
    result = requests.Response()
    result.status_code = status
    result.url = "http://backend.test/api/command"
    result._content = json.dumps({"success": True} if payload is None else payload).encode()
    result._content_consumed = True
    return result


def refused_connection():
    return requests.ConnectionError(MaxRetryError(
        None, "/api/command", NewConnectionError(None, "Connection refused"),
    ))


def invoke(server, name, **arguments):
    return asyncio.run(server.call_tool(name, arguments)).structured_content


@pytest.fixture
def http(monkeypatch):
    http = Mock(return_value=response())
    monkeypatch.setattr(requests.Session, "request", http)
    return http


@pytest.fixture
def sleep(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr(bear_mcp.time, "sleep", sleep)
    return sleep


@pytest.fixture
def bear_client():
    client = bear_mcp.BearClient("http://backend.test/")
    yield client
    client.session.close()


@pytest.fixture
def server(bear_client):
    return bear_mcp.setup_mcp_server(bear_client)


def test_offline_startup_registers_tools_without_http_or_sleep(monkeypatch, http, sleep):
    http.side_effect = AssertionError("Startup must not contact the backend")
    run = Mock()
    monkeypatch.setattr(FastMCP, "run", run)
    monkeypatch.setattr(bear_mcp.sys, "argv", ["bear-mcp", "--server", "http://offline.test"])

    bear_mcp.main()

    run.assert_called_once_with()
    http.assert_not_called()
    sleep.assert_not_called()


def test_registered_tools_recover_without_restarting_mcp(server, http, sleep):
    async def exercise():
        async with Client(server) as client:
            names = {tool.name for tool in await client.list_tools()}
            assert {"server_health", "disassemble_binary", "execute_command", "read_artifact"} <= names
            http.assert_not_called()

            http.side_effect = refused_connection()
            offline = await client.call_tool("execute_command", {"command": "true"})
            assert offline.data["success"] is False
            assert offline.data["error_code"] == "backend_unavailable"
            assert offline.data["retryable"] is True
            assert offline.data["outcome_unknown"] is False
            assert http.call_count == 3

            http.side_effect = None
            recovered = await client.call_tool("execute_command", {"command": "true"})
            assert recovered.data == {"success": True}

            http.side_effect = requests.ConnectionError("Backend restarting")
            assert (await client.call_tool("server_health")).data["success"] is False
            http.side_effect = None
            http.return_value = response({"status": "healthy"})
            assert (await client.call_tool("server_health")).data == {"status": "healthy"}
            assert {tool.name for tool in await client.list_tools()} == names

    asyncio.run(exercise())


def test_stdio_mcp_recovers_after_backend_restart(monkeypatch):
    processes = []
    open_process = anyio.open_process

    async def track_process(*args, **kwargs):
        # Observe real subprocess creation without replacing the stdio transport.
        process = await open_process(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(anyio, "open_process", track_process)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/health?verbose=true":
                self.send_error(404)
                return
            body = json.dumps({"status": "healthy", "generation": self.server.generation}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ExitStack() as listeners:
        # Bind without listening: offline calls refuse connections, and there is
        # no free-port probe/close race before the MCP subprocess starts.
        initial_backend = listeners.enter_context(ThreadingHTTPServer(
            ("127.0.0.1", 0), Handler, bind_and_activate=False,
        ))
        initial_backend.server_bind()
        address = initial_backend.server_address
        backend_url = f"http://127.0.0.1:{address[1]}"
        transport = StdioTransport(
            command=sys.executable,
            args=["-m", "bear.mcp", "--server", backend_url, "--timeout", "1"],
            cwd=str(Path(__file__).resolve().parents[1]),
            env={
                "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "",
                "http_proxy": "", "https_proxy": "", "all_proxy": "",
                "NO_PROXY": "*", "no_proxy": "*",
                "FASTMCP_CHECK_FOR_UPDATES": "off",
                "FASTMCP_SHOW_SERVER_BANNER": "false",
            },
            keep_alive=False,
        )

        async def exercise():
            backend = initial_backend
            async with Client(transport, timeout=5, init_timeout=10) as client:
                names = {tool.name for tool in await client.list_tools()}
                assert {"server_health", "execute_command", "disassemble_binary", "read_artifact"} <= names
                assert len(processes) == 1
                process = processes[0]
                session = client.session

                for generation in (1, 2):
                    offline = (await client.call_tool("server_health")).data
                    assert offline["success"] is False
                    assert offline["error_code"] == "backend_unavailable"
                    assert offline["server_url"] == backend_url
                    assert offline["retryable"] is True
                    assert offline["outcome_unknown"] is False
                    assert offline["attempts"] == 3

                    backend.generation = generation
                    backend.server_activate()
                    thread = threading.Thread(
                        target=backend.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
                    )
                    thread.start()
                    try:
                        healthy = (await client.call_tool("server_health")).data
                        assert healthy == {"status": "healthy", "generation": generation}
                        assert processes == [process]
                        assert process.returncode is None
                        assert client.session is session
                        assert {tool.name for tool in await client.list_tools()} == names
                    finally:
                        await asyncio.wait_for(asyncio.to_thread(backend.shutdown), timeout=3)
                        thread.join(timeout=3)
                        backend.server_close()
                        assert not thread.is_alive()

                    if generation == 1:
                        # Close and rebind the actual listener, rather than just
                        # pausing request handling. SO_REUSEADDR avoids TIME_WAIT;
                        # a port takeover fails at bind instead of hitting another service.
                        backend = listeners.enter_context(ThreadingHTTPServer(
                            address, Handler, bind_and_activate=False,
                        ))
                        backend.server_bind()

        async def run():
            try:
                await asyncio.wait_for(exercise(), timeout=30)
            finally:
                try:
                    await asyncio.wait_for(transport.close(), timeout=10)
                finally:
                    for process in processes:
                        if process.returncode is None:
                            process.kill()
                            await asyncio.wait_for(process.wait(), timeout=5)
            assert len(processes) == 1
            assert processes[0].returncode is not None

        asyncio.run(run())


@pytest.mark.parametrize("failure", [requests.ConnectTimeout("connect timeout"), refused_connection()])
def test_command_retries_only_known_connection_establishment_failures(bear_client, http, sleep, failure):
    http.side_effect = [failure, failure, response()]

    assert bear_client.execute_command("true", use_cache=False) == {"success": True}

    assert http.call_count == 3
    assert http.call_args_list == [call(
        "POST", "http://backend.test/api/command", timeout=(3, 300), allow_redirects=False,
        json={"command": "true", "use_cache": False, "async_mode": False, "timeout": 300},
    )] * 3
    assert sleep.call_args_list == [call(0.1), call(0.2)]


@pytest.mark.parametrize("method", ["POST", "DELETE"])
@pytest.mark.parametrize("failure", [
    requests.ReadTimeout("read timed out"),
    requests.Timeout("unknown timeout phase"),
    requests.ConnectionError("connection reset"),
    requests.ConnectionError(ProtocolError("Connection aborted", ConnectionResetError())),
    requests.ConnectionError(MaxRetryError(None, "/api/command", ReadTimeoutError(None, "", "read timeout"))),
    requests.exceptions.ChunkedEncodingError("incomplete response"),
    requests.exceptions.SSLError("TLS error"),
])
def test_mutations_are_not_replayed_after_ambiguous_failure(bear_client, http, sleep, method, failure):
    http.side_effect = [failure, response()]

    result = (bear_client.execute_command("true") if method == "POST"
              else bear_client.safe_delete("api/tasks/task-1"))

    assert result["success"] is False
    assert result["error_code"] == "backend_unavailable"
    assert result["attempts"] == 1
    assert result["retryable"] is False
    assert result["outcome_unknown"] is True
    assert "may have executed" in result["hint"]
    http.assert_called_once()
    sleep.assert_not_called()


def test_connect_retry_stops_as_soon_as_execution_becomes_uncertain(server, http, sleep):
    http.side_effect = [refused_connection(), requests.ReadTimeout("read timeout"), response()]

    result = invoke(server, "execute_command", command="true")

    assert result["attempts"] == 2
    assert result["retryable"] is False
    assert result["outcome_unknown"] is True
    assert result["endpoint"] == "api/command"
    assert result["server_url"] == "http://backend.test"
    assert "may have executed" in result["hint"]
    assert http.call_count == 2
    sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize("status", [307, 308, 400, 404, 429, 500, 502, 503, 504])
def test_mutations_do_not_retry_http_errors_or_follow_redirects(bear_client, http, sleep, status):
    http.return_value = response({"error": "backend error"}, status=status)

    result = bear_client.execute_command("true")

    assert result["success"] is False
    assert result["status_code"] == status
    assert result["retryable"] is False
    http.assert_called_once()
    assert http.call_args.kwargs["allow_redirects"] is False
    sleep.assert_not_called()


@pytest.mark.parametrize("failure", [
    requests.ReadTimeout("read timeout"),
    requests.ConnectionError("read reset"),
    requests.exceptions.ChunkedEncodingError("incomplete response"),
    response(status=502), response(status=503), response(status=504),
])
def test_get_retries_transient_failures_with_bounded_backoff(bear_client, http, sleep, failure):
    http.side_effect = [failure, failure, response({"status": "healthy"})]

    assert bear_client.check_health(verbose=True) == {"status": "healthy"}

    assert http.call_count == 3
    assert http.call_args.kwargs["params"] == {"verbose": "true"}
    assert sleep.call_args_list == [call(0.1), call(0.2)]


def test_get_retry_exhaustion_is_structured_and_later_call_recovers(bear_client, http, sleep):
    http.side_effect = requests.ReadTimeout("backend not responding")

    result = bear_client.safe_get("api/tasks")

    assert result["error_code"] == "backend_unavailable"
    assert result["retryable"] is True
    assert result["outcome_unknown"] is False
    assert result["attempts"] == 3
    assert http.call_count == 3
    assert sleep.call_args_list == [call(0.1), call(0.2)]
    http.side_effect = None
    assert bear_client.safe_get("api/tasks") == {"success": True}


@pytest.mark.parametrize("status", [400, 401, 404, 422])
def test_get_does_not_retry_nontransient_http_errors(bear_client, http, sleep, status):
    http.return_value = response(status=status)
    assert bear_client.check_health()["status_code"] == status
    http.assert_called_once()
    sleep.assert_not_called()


@pytest.mark.parametrize("body", [b"not json", b"[]", b"null"])
def test_invalid_response_is_structured_without_replay(bear_client, http, sleep, body):
    http.return_value._content = body
    result = bear_client.execute_command("true")
    assert result["error_code"] == "invalid_response"
    assert result["outcome_unknown"] is True
    http.assert_called_once()
    sleep.assert_not_called()


def test_real_refused_connection_is_safe_to_retry(sleep):
    # A bound, non-listening socket reserves a port that will refuse connects.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        client = bear_mcp.BearClient(f"http://127.0.0.1:{reserved.getsockname()[1]}", timeout=1)
        client.session.trust_env = False
        try:
            result = client.execute_command("true")
        finally:
            client.session.close()
    assert result["attempts"] == 3
    assert result["retryable"] is True
    assert result["outcome_unknown"] is False
    assert sleep.call_args_list == [call(0.1), call(0.2)]


@pytest.mark.parametrize("failure", ["reset", "timeout"])
def test_real_post_response_failure_does_not_execute_twice(failure):
    received = []
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            if failure == "timeout":
                release.wait(5)
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as backend:
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        client = bear_mcp.BearClient(f"http://127.0.0.1:{backend.server_port}")
        client.timeout = 0.05
        client.session.trust_env = False
        try:
            result = client.execute_command("true")
        finally:
            release.set()
            client.session.close()
            backend.shutdown()
            thread.join(timeout=5)

    assert len(received) == 1
    assert result["attempts"] == 1
    assert result["retryable"] is False
    assert result["outcome_unknown"] is True


@pytest.mark.parametrize("backend", ["auto", "ghidra", "objdump", " GHIDRA "])
def test_generic_disassembly_uses_backend_endpoint(server, http, backend):
    http.return_value = response({"success": True, "task_id": "task-1"})

    assert invoke(server, "disassemble_binary", binary="sample.exe", function="main",
                  backend=backend, timeout=600, async_mode=True) == {"success": True, "task_id": "task-1"}

    http.assert_called_once_with(
        "POST", "http://backend.test/api/tools/disassemble", timeout=(3, 300), allow_redirects=False,
        json={"binary": "sample.exe", "function": "main", "backend": backend.strip().lower(),
              "timeout": 600, "async_mode": True},
    )


def test_generic_disassembly_does_not_fallback_on_analysis_failure(server, http):
    payload = {"success": False, "backend": "ghidra", "error": "Analysis timed out"}
    http.return_value = response(payload)

    assert invoke(server, "disassemble_binary", binary="sample.exe") == payload

    http.assert_called_once()
    assert http.call_args.kwargs["json"] == {
        "binary": "sample.exe", "function": "all", "backend": "auto", "timeout": 300, "async_mode": False,
    }


def test_generic_disassembly_rejects_unknown_backend(server, http):
    assert invoke(server, "disassemble_binary", binary="sample.exe", backend="unknown")["success"] is False
    http.assert_not_called()


@pytest.mark.parametrize("name,arguments,endpoint,expected", [
    ("execute_command", {"command": "true"}, "api/command",
     {"command": "true", "use_cache": True, "async_mode": False, "timeout": 300}),
    ("execute_command", {"command": "true", "use_cache": False, "async_mode": True, "timeout": 12}, "api/command",
     {"command": "true", "use_cache": False, "async_mode": True, "timeout": 12}),
    ("execute_python_script", {"script": "pass"}, "api/python/execute",
     {"script": "pass", "env_name": "default", "async_mode": False, "timeout": 300}),
    ("execute_python_script", {"script": "pass", "env_name": "analysis", "filename": "job.py",
                               "async_mode": True, "timeout": 12}, "api/python/execute",
     {"script": "pass", "env_name": "analysis", "filename": "job.py", "async_mode": True, "timeout": 12}),
    ("strings_extract", {"file_path": "sample.exe"}, "api/tools/strings",
     {"file_path": "sample.exe", "min_len": 4, "encoding": "", "additional_args": "",
      "offset": 0, "max_scan_bytes": 16777216, "full_scan": False, "length": None,
      "max_strings": 1000, "include_resources": False, "async_mode": False}),
    ("strings_extract", {"file_path": "sample.exe", "min_len": 8, "encoding": "l", "additional_args": "-t x",
                         "offset": 128, "max_scan_bytes": 4096, "full_scan": True, "length": 8192,
                         "max_strings": 100, "include_resources": True}, "api/tools/strings",
     {"file_path": "sample.exe", "min_len": 8, "encoding": "l", "additional_args": "-t x",
      "offset": 128, "max_scan_bytes": 4096, "full_scan": True, "length": 8192,
      "max_strings": 100, "include_resources": True, "async_mode": False}),
    ("triage_binary", {"binary": "sample.exe"}, "api/tools/triage",
     {"binary": "sample.exe", "strings_limit": 40, "use_cache": True, "full_scan": False,
      "compute_hash": False, "offset": 0, "length": None, "max_scan_bytes": 16777216, "include_resources": False, "async_mode": False}),
    ("triage_binary", {"binary": "sample.exe", "strings_limit": 10, "use_cache": False, "full_scan": True,
                       "compute_hash": True, "offset": 128, "length": 4096,
                       "max_scan_bytes": 4096, "include_resources": True},
     "api/tools/triage", {"binary": "sample.exe", "strings_limit": 10, "use_cache": False, "full_scan": True,
                          "compute_hash": True, "offset": 128, "length": 4096,
                          "max_scan_bytes": 4096, "include_resources": True, "async_mode": False}),
])
def test_additive_post_options_are_forwarded(server, http, name, arguments, endpoint, expected):
    assert invoke(server, name, **arguments) == {"success": True}
    http.assert_called_once_with(
        "POST", f"http://backend.test/{endpoint}", timeout=(3, 300), allow_redirects=False, json=expected,
    )


@pytest.mark.parametrize("name,arguments,model", [
    ("strings_extract", {"file_path": "sample.exe"}, StringsRequest),
    ("triage_binary", {"binary": "sample.exe"}, TriageRequest),
])
def test_native_scan_payloads_match_parent_models(server, http, name, arguments, model):
    invoke(server, name, **arguments)
    payload = http.call_args.kwargs["json"]
    assert model.model_validate(payload).model_dump() == payload


@pytest.mark.parametrize("name,arguments,endpoint,expected", [
    ("pe_resources", {"binary": "sample.exe"}, "api/tools/pe/resources",
     {"binary": "sample.exe", "artifact_id": None, "resource_type": None, "resource_id": None,
      "language": None, "offset": 0, "limit": 100}),
    ("pe_resources_extract", {"binary": "sample.exe", "resource_id": 1}, "api/tools/pe/resources/extract",
     {"binary": "sample.exe", "artifact_id": None, "resource_type": 10, "resource_id": 1,
      "language": None, "max_bytes": 67108864}),
    ("pe_resources_batch", {"binary": "sample.exe", "operation": "sha256"}, "api/tools/pe/resources/batch",
     {"binary": "sample.exe", "artifact_id": None, "operation": "sha256", "resource_type": None,
      "resource_id": None, "language": None, "offset": 0, "limit": 100, "concurrency": 2,
      "max_bytes": 67108864, "max_total_bytes": 268435456, "result_offset": 0, "result_limit": 100}),
])
def test_resource_wrapper_defaults(server, http, name, arguments, endpoint, expected):
    assert invoke(server, name, **arguments) == {"success": True}
    http.assert_called_once_with(
        "POST", f"http://backend.test/{endpoint}", timeout=(3, 300), allow_redirects=False, json=expected,
    )


@pytest.mark.parametrize("name,arguments", [
    ("pe_resources", {"binary": None, "artifact_id": "artifact-1", "resource_type": "CUSTOM",
                      "resource_id": "PAYLOAD", "language": "en", "offset": 100, "limit": 25}),
    ("pe_resources_extract", {"binary": None, "artifact_id": "artifact-1", "resource_type": "CUSTOM",
                              "resource_id": "PAYLOAD", "language": 1033, "max_bytes": 4096}),
    ("pe_resources_batch", {"binary": None, "artifact_id": "artifact-1", "operation": "extract",
                            "resource_type": 10, "resource_id": "PAYLOAD", "language": 1033,
                            "offset": 100, "limit": 20, "concurrency": 4, "max_bytes": 4096,
                            "max_total_bytes": 81920, "result_offset": 5, "result_limit": 10}),
])
def test_resource_options_and_artifact_sources_are_forwarded(server, http, name, arguments):
    payload = {"success": True, "task_id": "task-1"}
    http.return_value = response(payload)
    assert invoke(server, name, **arguments) == payload
    assert http.call_args.kwargs["json"] == arguments
    http.assert_called_once()


@pytest.mark.parametrize("name,arguments,endpoint,params", [
    ("list_async_tasks", {}, "api/tasks", {"offset": 0, "limit": 50}),
    ("list_async_tasks", {"offset": 50, "limit": 10}, "api/tasks", {"offset": 50, "limit": 10}),
    ("read_artifact", {"artifact_id": "artifact-1"}, "api/artifacts/artifact-1", {"offset": 0, "limit": 8192}),
    ("read_artifact", {"artifact_id": "artifact-1", "offset": 8192, "limit": 64},
     "api/artifacts/artifact-1", {"offset": 8192, "limit": 64}),
    ("read_artifact", {"artifact_id": "id?#/other"}, "api/artifacts/id%3F%23%2Fother", {"offset": 0, "limit": 8192}),
])
def test_paged_get_options_are_forwarded(server, http, name, arguments, endpoint, params):
    payload = {"success": True, "data_base64": "AAEC", "next_offset": 3}
    http.return_value = response(payload)
    assert invoke(server, name, **arguments) == payload
    http.assert_called_once_with(
        "GET", f"http://backend.test/{endpoint}", timeout=(3, 300), allow_redirects=False, params=params,
    )


@pytest.mark.parametrize("arguments", [
    {"artifact_id": ""}, {"artifact_id": "."}, {"artifact_id": ".."},
    {"artifact_id": "id", "offset": -1}, {"artifact_id": "id", "limit": 0},
    {"artifact_id": "id", "limit": 8193},
])
def test_artifact_pages_are_bounded_before_http(server, http, arguments):
    assert invoke(server, "read_artifact", **arguments)["success"] is False
    http.assert_not_called()


@pytest.mark.parametrize("name,arguments", [
    ("execute_command", {"command": "true"}),
    ("execute_python_script", {"script": "pass"}),
    ("disassemble_binary", {"binary": "sample.exe"}),
    ("get_task_status", {"task_id": "task-1"}),
])
def test_large_output_envelopes_pass_through_without_fetching_artifact(server, http, name, arguments):
    payload = {"success": True, "truncated": True,
               "artifact": {"artifact_id": "artifact-1", "size_bytes": 1000000}, "preview": "partial output"}
    http.return_value = response(payload)
    assert invoke(server, name, **arguments) == payload
    http.assert_called_once()


def test_command_preserves_artifact_metadata_on_failure(server, http):
    payload = {"success": False, "error": "Command failed", "truncated": True,
               "artifact": {"artifact_id": "artifact-1", "size_bytes": 1000000}, "preview": "partial output"}
    http.return_value = response(payload)
    result = invoke(server, "execute_command", command="false")
    assert payload.items() <= result.items()
    http.assert_called_once()
