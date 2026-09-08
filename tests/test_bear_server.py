"""
BEAR Server Unit Tests
Tests for the BEAR API endpoints with mocked command execution
"""

import os
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

import bear.server as bear_server
from bear.server import app


@pytest.fixture
def client():
    """Create a test client for the FastAPI app"""
    yield TestClient(app)


@pytest.fixture
def mock_execute_command():
    """Mock the execute_command function"""
    with patch('bear.server.execute_command') as mock:
        yield mock


class TestHealthEndpoints:
    """Tests for health and status endpoints"""

    def test_health_check(self, client):
        """Test /health endpoint returns OK"""
        response = client.get('/health')
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'healthy'

    def test_cache_stats(self, client):
        """Test /api/cache/stats endpoint"""
        response = client.get('/api/cache/stats')
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)


class TestTriageEndpoints:
    """Tests for binary triage endpoint"""

    @patch('bear.server.execute_command')
    def test_triage_binary_success(self, mock_execute, client, tmp_path):
        """Test successful binary triage"""
        import hashlib

        binary = tmp_path / 'test.elf'
        binary.write_bytes(b'\x7fELF\0hello\0world\0')
        mock_execute.side_effect = [
            {'success': True, 'stdout': 'NX enabled', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'ELF Header', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'Symbol table', 'stderr': '', 'return_code': 0},
        ]

        response = client.post('/api/tools/triage', json={'binary': str(binary), 'compute_hash': True})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['summary']['sha256'] == hashlib.sha256(binary.read_bytes()).hexdigest()
        assert 'checksec' in data['checks']
        assert mock_execute.call_count == 3

    def test_triage_binary_missing_binary(self, client):
        """Test triage validation when binary is missing"""
        response = client.post('/api/tools/triage', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data


@pytest.fixture
def ghidra_files(tmp_path, monkeypatch):
    import shlex
    from pathlib import Path

    binary = tmp_path / "a binary 'with quotes' $(touch nope)"
    binary.write_bytes(b"binary version one")
    headless = tmp_path / "Ghidra installation" / "support" / "analyzeHeadless"
    headless.parent.mkdir(parents=True)
    headless.write_text("launcher version one")
    properties = headless.parent.parent / "Ghidra" / "application.properties"
    properties.parent.mkdir()
    properties.write_text("application.version=12.1")
    monkeypatch.setenv("BEAR_GHIDRA_PROJECT_DIR", str(tmp_path / "projects"))
    monkeypatch.setattr(bear_server, "find_ghidra_headless", lambda: str(headless))
    monkeypatch.setattr(bear_server, "check_task_cancelled", lambda: None, raising=False)
    monkeypatch.setattr(bear_server, "update_task_progress", lambda **fields: None, raising=False)
    output = MagicMock(return_value={
        "success": True, "return_code": 0,
        "stdout": ('===BEAR_JSON_START===\n{"functions": []}\n===BEAR_JSON_END===\n'
                   'INFO REPORT: Save succeeded\nINFO REPORT: Import succeeded'),
        "stderr": "",
    })

    def execute(command, **kwargs):
        argv = shlex.split(command)
        project = Path(argv[1])
        (project / "bear_project.gpr").touch()
        (project / "bear_project.rep").mkdir(exist_ok=True)
        return output(command, **kwargs)

    monkeypatch.setattr(bear_server, "execute_command", execute)
    return binary, headless, output


class TestGhidraEndpoints:
    """Tests for Ghidra-related endpoints"""

    @patch('glob.glob')
    @patch('bear.server.shutil.which')
    @patch('bear.server.os.path.exists')
    def test_find_ghidra_headless_searches_home_ghidra(self, mock_exists,
                                                       mock_which, mock_glob):
        """Test Ghidra discovery supports ~/Ghidra/<version> installs."""
        expected = os.path.expanduser('~/Ghidra/ghidra_12.1_PUBLIC/support/analyzeHeadless')
        mock_which.return_value = None
        mock_exists.return_value = False
        mock_glob.side_effect = (
            lambda pattern: [expected]
            if pattern == os.path.expanduser('~/Ghidra/*/support/analyzeHeadless')
            else []
        )

        assert bear_server.find_ghidra_headless() == expected

    def test_ghidra_decompile_missing_binary(self, client):
        """Test ghidra/decompile endpoint returns error when binary is missing"""
        response = client.post('/api/tools/ghidra/decompile', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    def test_ghidra_decompile_binary_not_found(self, client):
        """Test ghidra/decompile returns error for non-existent binary"""
        response = client.post('/api/tools/ghidra/decompile', json={'binary': '/nonexistent/binary'})
        assert response.status_code == 400
        data = response.json()
        assert 'not found' in data['error'].lower()

    def test_ghidra_decompile_success(self, ghidra_files, client):
        """Test successful ghidra decompilation"""
        binary, _, mock_execute = ghidra_files
        mock_execute.return_value = {
            'success': True,
            'stdout': '''INFO Analysis complete
===BEAR_JSON_START===
{
  "binary": "/tmp/test",
  "format": "ELF",
  "functions": [
    {
      "name": "main",
      "address": "0x401000",
      "signature": "int main(int argc, char **argv)",
      "code": "int main() { return 0; }"
    }
  ]
}
===BEAR_JSON_END===
INFO REPORT: Save succeeded
INFO REPORT: Import succeeded''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/decompile', json={'binary': str(binary), 'function': 'main'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert 'decompiled' in data
        assert len(data['decompiled']['functions']) == 1
        assert data['decompiled']['functions'][0]['name'] == 'main'

    def test_ghidra_disassemble_success(self, ghidra_files, client):
        """Test successful ghidra disassembly"""
        binary, _, mock_execute = ghidra_files
        mock_execute.return_value = {
            'success': True,
            'stdout': '''INFO Analysis complete
===BEAR_JSON_START===
{
  "binary": "/tmp/test",
  "format": "ELF",
  "functions": [
    {
      "name": "main",
      "address": "0x401000",
      "instructions": [
        {"address": "0x401000", "mnemonic": "PUSH", "operands": "RBP", "bytes": "55"}
      ]
    }
  ]
}
===BEAR_JSON_END===
INFO REPORT: Save succeeded
INFO REPORT: Import succeeded''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/disassemble', json={'binary': str(binary), 'function': 'main'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert 'disassembled' in data
        assert len(data['disassembled']['functions']) == 1
        assert data['disassembled']['functions'][0]['instructions'][0]['mnemonic'] == 'PUSH'

    def test_ghidra_functions_success(self, ghidra_files, client):
        """Test successful ghidra function listing"""
        binary, _, mock_execute = ghidra_files
        mock_execute.return_value = {
            'success': True,
            'stdout': '''INFO Analysis complete
===BEAR_JSON_START===
{
  "binary": "/tmp/test",
  "format": "ELF",
  "functions": [
    {"name": "main", "address": "0x401000", "namespace": "Global", "signature": "int main()", "size": 42}
  ]
}
===BEAR_JSON_END===
INFO REPORT: Save succeeded
INFO REPORT: Import succeeded''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/functions', json={'binary': str(binary)})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['mode'] == 'functions'
        assert data['functions'][0]['name'] == 'main'

    def test_ghidra_xrefs_success(self, ghidra_files, client):
        """Test successful ghidra xrefs"""
        binary, _, mock_execute = ghidra_files
        mock_execute.return_value = {
            'success': True,
            'stdout': '''INFO Analysis complete
===BEAR_JSON_START===
{
  "binary": "/tmp/test",
  "format": "ELF",
  "target": "strcpy",
  "target_type": "symbol",
  "resolved_addresses": ["0x401030"],
  "xrefs_to": [
    {"from_address": "0x401200", "to_address": "0x401030", "from_function": "vuln", "to_function": "", "reference_type": "CALL"}
  ],
  "xrefs_from": []
}
===BEAR_JSON_END===
INFO REPORT: Save succeeded
INFO REPORT: Import succeeded''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/xrefs', json={'binary': str(binary), 'target': 'strcpy'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['mode'] == 'xrefs'
        assert data['xrefs_to'][0]['from_function'] == 'vuln'

    def test_ghidra_callgraph_success(self, ghidra_files, client):
        """Test successful ghidra callgraph"""
        binary, _, mock_execute = ghidra_files
        mock_execute.return_value = {
            'success': True,
            'stdout': '''INFO Analysis complete
===BEAR_JSON_START===
{
  "binary": "/tmp/test",
  "format": "ELF",
  "function": "main",
  "direction": "out",
  "depth": 2,
  "callgraph": {
    "main": ["parse_args", "vuln"]
  }
}
===BEAR_JSON_END===
INFO REPORT: Save succeeded
INFO REPORT: Import succeeded''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/callgraph', json={'binary': str(binary), 'function': 'main'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['mode'] == 'callgraph'
        assert 'vuln' in data['callgraph']['main']

    def test_reuse_across_all_modes_and_invalidation(self, ghidra_files, client):
        import shlex

        binary, headless, execute = ghidra_files
        for mode in ('decompile', 'disassemble', 'functions', 'xrefs', 'callgraph'):
            params = {'binary': str(binary)}
            if mode == 'xrefs':
                params['target'] = 'main'
            assert client.post('/api/tools/ghidra/' + mode, json=params).json()['success']
        commands = [shlex.split(call.args[0]) for call in execute.call_args_list]
        assert '-import' in commands[0]
        assert all('-process' in argv and '-noanalysis' in argv for argv in commands[1:])
        assert len({argv[1] for argv in commands}) == 1
        assert all(call.kwargs['use_cache'] is False for call in execute.call_args_list)
        assert all('-deleteProject' not in argv for argv in commands)
        # Preserve size/mtime to ensure content changes are not missed by a stat-only key.
        old_stat = binary.stat()
        binary.write_bytes(b'binary version two')
        os.utime(binary, ns=(old_stat.st_atime_ns, old_stat.st_mtime_ns))
        assert client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()['success']
        changed = shlex.split(execute.call_args.args[0])
        assert '-import' in changed and changed[1] != commands[0][1]
        properties = headless.parent.parent / 'Ghidra' / 'application.properties'
        properties.write_text('application.version=12.2')
        assert client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()['success']
        upgraded = shlex.split(execute.call_args.args[0])
        assert '-import' in upgraded and upgraded[1] != changed[1]
        headless.write_text('launcher version two')
        assert client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()['success']
        assert '-import' in shlex.split(execute.call_args.args[0])

    def test_four_parallel_calls_serialize_one_import(self, ghidra_files):
        import shlex
        import threading
        import time
        from concurrent.futures import ThreadPoolExecutor

        binary, _, execute = ghidra_files
        barrier = threading.Barrier(4)
        active = 0
        maximum = 0
        guard = threading.Lock()
        success = execute.return_value

        def slow_execute(*args, **kwargs):
            nonlocal active, maximum
            with guard:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.08)
            with guard:
                active -= 1
            return success

        execute.side_effect = slow_execute

        def request(_):
            barrier.wait(timeout=5)
            return bear_server.ghidra_functions(bear_server.GhidraFunctionsRequest(binary=str(binary)))

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(request, range(4)))
        assert all(result['success'] for result in results)
        assert maximum == 1
        commands = [shlex.split(call.args[0]) for call in execute.call_args_list]
        assert sum('-import' in argv for argv in commands) == 1
        assert sum('-process' in argv for argv in commands) == 3
        assert len({argv[1] for argv in commands}) == 1

    @pytest.mark.parametrize('failure', [
        {'success': False, 'stderr': 'import failed'},
        {'success': False, 'timed_out': True},
        {'success': True, 'timed_out': True},
        {'success': True, 'return_code': 1},
        {'success': True, 'stdout': 'no JSON'},
        {'success': True, 'stdout': '===BEAR_JSON_START===[]===BEAR_JSON_END==='},
        {'success': True, 'stdout': '===BEAR_JSON_START==={"functions": []}===BEAR_JSON_END===\nERROR Save failed'},
    ])
    @pytest.mark.parametrize('already_ready', [False, True])
    def test_failure_recovery(self, failure, already_ready, ghidra_files, client):
        import shlex

        binary, _, execute = ghidra_files
        params = {'binary': str(binary)}
        if already_ready:
            assert client.post('/api/tools/ghidra/functions', json=params).json()['success']
        success = execute.return_value
        execute.return_value = failure
        assert not client.post('/api/tools/ghidra/functions', json=params).json()['success']
        failed_dir = shlex.split(execute.call_args.args[0])[1]
        execute.return_value = success
        assert client.post('/api/tools/ghidra/functions', json=params).json()['success']
        recovered = shlex.split(execute.call_args.args[0])
        assert '-import' in recovered
        assert recovered[1] != failed_dir

    def test_exception_does_not_poison_project(self, ghidra_files):
        import shlex

        binary, _, execute = ghidra_files
        params = bear_server.GhidraFunctionsRequest(binary=str(binary))
        execute.side_effect = RuntimeError('executor interrupted')
        with pytest.raises(RuntimeError, match='interrupted'):
            bear_server.ghidra_functions(params)
        failed = shlex.split(execute.call_args.args[0])[1]
        execute.side_effect = None
        assert bear_server.ghidra_functions(params)['success']
        recovered = shlex.split(execute.call_args.args[0])
        assert '-import' in recovered and recovered[1] != failed

    @pytest.mark.parametrize('mode', ['decompile', 'disassemble', 'functions', 'xrefs', 'callgraph', 'generic'])
    def test_async_parse_parity(self, mode, ghidra_files, client, monkeypatch):
        binary, _, execute = ghidra_files
        queued = []

        def submit(operation, label):
            queued.append(operation)
            return {'success': True, 'async': True, 'task_id': 'task-1', 'status': 'queued'}

        monkeypatch.setattr(bear_server, 'submit_task', submit, raising=False)
        params = {'binary': str(binary)}
        if mode == 'xrefs':
            params['target'] = 'main'
        route = '/api/tools/disassemble' if mode == 'generic' else '/api/tools/ghidra/' + mode
        sync_result = client.post(route, json=params).json()
        response = client.post(route, json={**params, 'async_mode': True}).json()
        assert response['task_id'] == 'task-1'
        assert execute.call_count == 1
        assert queued.pop()() == sync_result

    def test_full_artifact_is_parsed_not_preview(self, ghidra_files, client, monkeypatch, tmp_path):
        import json
        from bear import artifacts

        monkeypatch.setenv('BEAR_ARTIFACT_DIR', str(tmp_path / 'artifacts'))
        binary, _, execute = ghidra_files
        payload = {'functions': [{'name': 'main', 'code': 'x' * 100000 + '===BEAR_JSON_END==='}]}
        output = tmp_path / 'full-output'
        output.write_text('log\n===BEAR_JSON_START===\n' + json.dumps(payload)
                          + '\n===BEAR_JSON_END===\nINFO REPORT: Save succeeded\nINFO REPORT: Import succeeded')
        execute.return_value = {'success': True, 'stdout': 'log\n===BEAR_JSON_ST',
                                'stdout_artifact': artifacts.store_file(output)}
        result = client.post('/api/tools/ghidra/decompile', json={'binary': str(binary)}).json()
        assert result['truncated']
        result = json.loads(artifacts.artifact_path(result['artifact']['artifact_id']).read_bytes())
        assert result['success'] and result['decompiled'] == payload

    @pytest.mark.parametrize('backend', ['auto', 'ghidra'])
    def test_default_disassembly_uses_ghidra(self, backend, ghidra_files, client):
        import shlex

        binary, _, execute = ghidra_files
        params = {'binary': str(binary)}
        if backend != 'auto':
            params['backend'] = backend
        result = client.post('/api/tools/disassemble', json=params).json()
        assert result['success'] and result['backend'] == 'ghidra'
        assert 'disassembled' in result
        assert 'DisassembleFunction.java' in shlex.split(execute.call_args.args[0])

    def test_disassembly_does_not_fallback_on_ghidra_failure(self, ghidra_files, client):
        binary, _, execute = ghidra_files
        execute.return_value = {'success': False, 'stderr': 'analysis failed'}
        result = client.post('/api/tools/disassemble', json={'binary': str(binary)}).json()
        assert not result['success'] and result['backend'] == 'ghidra'
        assert execute.call_count == 1

    @pytest.mark.parametrize('mode,payload', [
        ('decompile', {'functions': [], 'error': 'Function not found'}),
        ('disassemble', {'functions': [], 'error': 'Function not found'}),
        ('decompile', {'functions': [{'name': 'one', 'error': 'Timed out'}, {'name': 'two', 'code': 'return;'}]}),
        ('xrefs', {'error': 'Target not found'}),
    ])
    def test_query_errors_are_failures_without_losing_saved_project(self, ghidra_files, client, mode, payload):
        import json
        import shlex

        binary, _, execute = ghidra_files
        execute.return_value = {'success': True, 'stdout':
            '===BEAR_JSON_START===\n' + json.dumps(payload)
            + '\n===BEAR_JSON_END===\nINFO REPORT: Save succeeded\nINFO REPORT: Import succeeded'}
        params = {'binary': str(binary), **({'target': 'missing'} if mode == 'xrefs' else {})}
        first = client.post('/api/tools/ghidra/' + mode, json=params).json()
        assert first['success'] is False and first['error']
        assert first['partial'] == bool(payload.get('functions'))
        assert '-import' in shlex.split(execute.call_args.args[0])
        second = client.post('/api/tools/ghidra/' + mode, json=params).json()
        assert second['success'] is False
        assert '-process' in shlex.split(execute.call_args.args[0])

    @pytest.mark.parametrize('backend', ['auto', 'objdump', 'ghidra'])
    def test_disassembly_backend_when_ghidra_unavailable(self, backend, ghidra_files, client, monkeypatch):
        import shlex

        binary, _, _ = ghidra_files
        monkeypatch.setattr(bear_server, 'find_ghidra_headless', lambda: None)
        execute = MagicMock(return_value={'success': True, 'stdout': 'assembly'})
        monkeypatch.setattr(bear_server, 'execute_command', execute)
        response = client.post('/api/tools/disassemble', json={'binary': str(binary), 'backend': backend})
        if backend == 'ghidra':
            assert response.status_code == 400
            execute.assert_not_called()
        else:
            assert response.json()['backend'] == 'objdump'
            assert shlex.split(execute.call_args.args[0]) == ['objdump', '-M', 'intel', '-d', '--', str(binary)]

    def test_argv_quotes_targets_and_rejects_headless_flags(self, ghidra_files, client):
        import shlex

        binary, headless, execute = ghidra_files
        target = 'name "quoted" $(touch nope); `id`'
        response = client.post('/api/tools/ghidra/decompile', json={'binary': str(binary), 'function': target})
        assert response.json()['success']
        argv = shlex.split(execute.call_args.args[0])
        assert argv[0] == str(headless)
        assert argv[argv.index('-import') + 1] == str(binary)
        assert argv[-1] == target
        response = client.post('/api/tools/ghidra/decompile',
                               json={'binary': str(binary), 'function': '-deleteProject'})
        assert response.status_code == 400
        assert execute.call_count == 1

    def test_four_processes_share_os_lock(self, ghidra_files):
        import json
        import subprocess
        import sys

        binary, headless, _ = ghidra_files
        script = '''
import json, sys, time
from bear.ghidra import run_project
def operation(project, reuse):
    sentinel = project.parent / 'executing'
    with sentinel.open('x'):
        time.sleep(0.2)
        (project / 'bear_project.gpr').touch()
        (project / 'bear_project.rep').mkdir(exist_ok=True)
    sentinel.unlink()
    return {'success': True, 'reuse': reuse, 'project': str(project)}
print(json.dumps(run_project(sys.argv[1], sys.argv[2], operation, lambda: None, lambda **kw: None)))
'''
        processes = [subprocess.Popen([sys.executable, '-c', script, str(binary), str(headless)],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for _ in range(4)]
        try:
            outputs = [process.communicate(timeout=15) for process in processes]
            assert all(process.returncode == 0 for process in processes), outputs
            results = [json.loads(stdout) for stdout, _ in outputs]
            assert sum(result['reuse'] for result in results) == 3
            assert len({result['project'] for result in results}) == 1
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait()

    def test_cancel_while_waiting_for_project_lock(self, ghidra_files, monkeypatch):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        binary, _, execute = ghidra_files
        holding = threading.Event()
        release = threading.Event()
        waiting = threading.Event()
        cancelled = threading.Event()
        local = threading.local()
        success = execute.return_value

        def hold(*args, **kwargs):
            holding.set()
            assert release.wait(timeout=5)
            return success

        def check():
            if getattr(local, 'waiter', False) and cancelled.is_set():
                raise RuntimeError('task cancelled')

        def progress(**fields):
            if getattr(local, 'waiter', False) and fields.get('stage') == 'waiting_for_project':
                waiting.set()

        def request(waiter=False):
            local.waiter = waiter
            return bear_server.ghidra_functions(bear_server.GhidraFunctionsRequest(binary=str(binary)))

        execute.side_effect = hold
        monkeypatch.setattr(bear_server, 'check_task_cancelled', check)
        monkeypatch.setattr(bear_server, 'update_task_progress', progress)
        with ThreadPoolExecutor(max_workers=2) as pool:
            owner = pool.submit(request)
            try:
                assert holding.wait(timeout=5)
                waiter = pool.submit(request, True)
                assert waiting.wait(timeout=5)
                cancelled.set()
                with pytest.raises(RuntimeError, match='cancelled'):
                    waiter.result(timeout=2)
            finally:
                release.set()
            assert owner.result(timeout=5)['success']
        assert execute.call_count == 1

    def test_changed_during_analysis_is_not_reused(self, ghidra_files, client):
        import shlex

        binary, _, execute = ghidra_files
        success = execute.return_value

        def mutate(*args, **kwargs):
            binary.write_bytes(b'changed while Ghidra was running')
            return success

        execute.side_effect = mutate
        result = client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()
        assert not result['success'] and 'changed' in result['error']
        execute.side_effect = None
        assert client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()['success']
        assert '-import' in shlex.split(execute.call_args.args[0])

    def test_missing_project_files_are_not_marked_ready(self, ghidra_files, client, monkeypatch):
        import shlex

        binary, _, output = ghidra_files
        real_fixture_execute = bear_server.execute_command
        execute = MagicMock(return_value=output.return_value)
        monkeypatch.setattr(bear_server, 'execute_command', execute)
        result = client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()
        assert not result['success'] and 'save' in result['error']
        failed = shlex.split(execute.call_args.args[0])[1]
        monkeypatch.setattr(bear_server, 'execute_command', real_fixture_execute)
        assert client.post('/api/tools/ghidra/functions', json={'binary': str(binary)}).json()['success']
        recovered = shlex.split(output.call_args.args[0])
        assert '-import' in recovered and recovered[1] != failed

    def test_hidden_project_path_rejected_before_launch(self, ghidra_files, client, monkeypatch, tmp_path):
        binary, _, execute = ghidra_files
        monkeypatch.setenv('BEAR_GHIDRA_PROJECT_DIR', str(tmp_path / '.cache' / 'ghidra'))
        response = client.post('/api/tools/ghidra/functions', json={'binary': str(binary)})
        assert response.status_code == 400
        assert 'hidden path' in response.json()['error']
        execute.assert_not_called()

    def test_explicit_objdump_does_not_discover_ghidra(self, ghidra_files, client, monkeypatch):
        binary, _, _ = ghidra_files
        discover = MagicMock(side_effect=AssertionError('must not discover Ghidra'))
        execute = MagicMock(return_value={'success': True, 'stdout': 'assembly'})
        monkeypatch.setattr(bear_server, 'find_ghidra_headless', discover)
        monkeypatch.setattr(bear_server, 'execute_command', execute)
        response = client.post('/api/tools/disassemble', json={'binary': str(binary), 'backend': 'objdump'})
        assert response.json()['backend'] == 'objdump'
        discover.assert_not_called()


class TestGDBEndpoints:
    """Tests for GDB-related endpoints"""

    def test_gdb_missing_params(self, client):
        """Test gdb endpoint returns error when no params provided"""
        response = client.post('/api/tools/gdb', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_gdb_with_binary(self, mock_execute, client):
        """Test gdb with binary parameter"""
        mock_execute.return_value = {
            'success': True,
            'stdout': 'GNU gdb output',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/gdb', json={'binary': '/bin/ls'})
        assert response.status_code == 200
        mock_execute.assert_called_once()


class TestRadare2Endpoints:
    """Tests for Radare2-related endpoints"""

    def test_radare2_missing_binary(self, client):
        """Test radare2 endpoint returns error when binary is missing"""
        response = client.post('/api/tools/radare2', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    @patch('os.path.exists')
    @patch('builtins.open', create=True)
    def test_radare2_with_commands(self, mock_open, mock_exists, mock_execute, client):
        """Test radare2 with commands"""
        mock_exists.return_value = True
        mock_execute.return_value = {
            'success': True,
            'stdout': 'radare2 output',
            'stderr': '',
            'return_code': 0
        }
        mock_open.return_value.__enter__ = MagicMock()
        mock_open.return_value.__exit__ = MagicMock()

        response = client.post('/api/tools/radare2', json={'binary': '/bin/ls', 'commands': 'aaa; afl'})
        assert response.status_code == 200


class TestBinwalkEndpoints:
    """Tests for Binwalk-related endpoints"""

    def test_binwalk_missing_file(self, client):
        """Test binwalk endpoint returns error when file is missing"""
        response = client.post('/api/tools/binwalk', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_binwalk_basic(self, mock_execute, client):
        """Test basic binwalk analysis"""
        mock_execute.return_value = {
            'success': True,
            'stdout': 'DECIMAL       HEXADECIMAL     DESCRIPTION',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/binwalk', json={'file_path': '/tmp/firmware.bin'})
        assert response.status_code == 200


class TestChecksecEndpoints:
    """Tests for Checksec-related endpoints"""

    def test_checksec_missing_binary(self, client):
        """Test checksec endpoint returns error when binary is missing"""
        response = client.post('/api/tools/checksec', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_checksec_basic(self, mock_execute, client):
        """Test basic checksec"""
        mock_execute.return_value = {
            'success': True,
            'stdout': 'RELRO: Full RELRO\nStack: Canary found\nNX: NX enabled\nPIE: PIE enabled',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/checksec', json={'binary': '/bin/ls'})
        assert response.status_code == 200


class TestROPgadgetEndpoints:
    """Tests for ROPgadget-related endpoints"""

    def test_ropgadget_missing_binary(self, client):
        """Test ropgadget endpoint returns error when binary is missing"""
        response = client.post('/api/tools/ropgadget', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_ropgadget_basic(self, mock_execute, client):
        """Test basic ROPgadget search"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '0x0000000000401234 : pop rdi ; ret',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ropgadget', json={'binary': '/bin/ls'})
        assert response.status_code == 200


class TestStringsEndpoints:
    """Tests for Strings-related endpoints"""

    def test_strings_missing_file(self, client):
        """Test strings endpoint returns error when file is missing"""
        response = client.post('/api/tools/strings', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_strings_basic(self, mock_execute, client):
        """Test basic strings extraction"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '/lib64/ld-linux-x86-64.so.2\nlibc.so.6\nputs',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/strings', json={'file_path': '/bin/ls'})
        assert response.status_code == 200


class TestObjdumpEndpoints:
    """Tests for Objdump-related endpoints"""

    def test_objdump_missing_binary(self, client):
        """Test objdump endpoint returns error when binary is missing"""
        response = client.post('/api/tools/objdump', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_objdump_disassemble(self, mock_execute, client):
        """Test objdump disassembly"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '0000000000401000 <main>:\n  401000: 55    push   %rbp',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/objdump', json={'binary': '/bin/ls', 'disassemble': True})
        assert response.status_code == 200


class TestOneGadgetEndpoints:
    """Tests for One-Gadget-related endpoints"""

    def test_one_gadget_missing_libc(self, client):
        """Test one-gadget endpoint returns error when libc_path is missing"""
        response = client.post('/api/tools/one-gadget', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data

    @patch('bear.server.execute_command')
    def test_one_gadget_basic(self, mock_execute, client):
        """Test basic one-gadget search"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '0x4f2a5 execve("/bin/sh", rsp+0x40, environ)',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/one-gadget', json={'libc_path': '/lib/x86_64-linux-gnu/libc.so.6'})
        assert response.status_code == 200



class TestAsyncTasks:
    """Tests for async task submission and polling endpoints"""

    def test_list_tasks_empty(self, client):
        """Test /api/tasks returns empty list when no tasks submitted"""
        original = dict(bear_server.task_results)
        bear_server.task_results.clear()
        response = client.get('/api/tasks')
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['total'] == 0
        assert data['tasks'] == []
        bear_server.task_results.update(original)

    def test_get_task_not_found(self, client):
        """Test GET /api/tasks/<task_id> returns 404 for unknown task"""
        response = client.get('/api/tasks/nonexistent_task_id')
        assert response.status_code == 404
        data = response.json()
        assert 'error' in data

    def test_cancel_task_not_found(self, client):
        """Test DELETE /api/tasks/<task_id> returns 404 for unknown task"""
        response = client.delete('/api/tasks/nonexistent_task_id')
        assert response.status_code == 404
        data = response.json()
        assert 'error' in data

    def test_get_task_queued(self, client):
        """Test GET /api/tasks/<task_id> returns queued status"""
        task_id = 'test_task_queued_123'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'queued',
            'submitted_at': 1000.0, 'started_at': None,
            'completed_at': None, 'command': 'python3 /tmp/test.py', 'result': None,
        }
        response = client.get(f'/api/tasks/{task_id}')
        assert response.status_code == 200
        data = response.json()
        assert data['task_id'] == task_id
        assert data['status'] == 'queued'
        assert 'result' not in data
        del bear_server.task_results[task_id]

    def test_get_task_completed(self, client):
        """Test GET /api/tasks/<task_id> returns result when completed"""
        task_id = 'test_task_done_456'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'completed',
            'submitted_at': 1000.0, 'started_at': 1001.0, 'completed_at': 1060.0,
            'command': 'python3 /tmp/ghidra_analysis.py',
            'result': {'success': True, 'stdout': 'done', 'execution_time': 59.0},
        }
        response = client.get(f'/api/tasks/{task_id}')
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'completed'
        assert data['result']['success'] is True
        del bear_server.task_results[task_id]

    def test_cancel_completed_task_fails(self, client):
        """Test that cancelling a completed task returns 400"""
        task_id = 'test_task_cancel_789'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'completed',
            'submitted_at': 1000.0, 'started_at': 1001.0, 'completed_at': 1060.0,
            'command': 'python3 /tmp/test.py', 'result': {'success': True},
        }
        response = client.delete(f'/api/tasks/{task_id}')
        assert response.status_code == 400
        data = response.json()
        assert data['success'] is False
        del bear_server.task_results[task_id]

    def test_list_tasks_with_entries(self, client):
        """Test /api/tasks lists all submitted tasks"""
        task_id = 'test_list_task_abc'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'running',
            'submitted_at': 1000.0, 'started_at': 1001.0,
            'completed_at': None, 'command': 'python3 /tmp/ghidra.py', 'result': None,
        }
        response = client.get('/api/tasks')
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        task_ids = [t['task_id'] for t in data['tasks']]
        assert task_id in task_ids
        del bear_server.task_results[task_id]


@pytest.fixture
def task_client(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv('BEAR_ARTIFACT_DIR', str(tmp_path / 'artifacts'))
    monkeypatch.setattr(bear_server, 'task_results', {})
    monkeypatch.setattr(bear_server, 'task_executor', None)
    monkeypatch.setattr(bear_server, 'task_context', threading.local())
    monkeypatch.setattr(bear_server, 'TASK_WORKERS', 2)
    monkeypatch.setattr(bear_server, 'MAX_PENDING_TASKS', 10)
    monkeypatch.setattr(bear_server, 'python_env_manager', bear_server.PythonEnvironmentManager(str(tmp_path / 'envs')))
    with TestClient(app) as test_client:
        yield test_client


def wait_for_task(client, task_id, predicate=lambda result: result['status'] in ('completed', 'failed', 'cancelled')):
    import time

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        response = client.get(f'/api/tasks/{task_id}')
        assert response.status_code == 200
        result = response.json()
        if predicate(result):
            return result
        time.sleep(0.01)
    pytest.fail(f'Task did not reach expected state: {result}')


class TestTaskExecution:
    def test_command_async_has_bounded_result_and_lossless_artifacts(self, task_client):
        import base64
        import json
        import shlex
        import sys
        from bear import artifacts

        command = shlex.join([sys.executable, '-c', 'print("x" * 100000)'])
        submission = task_client.post('/api/command', json={
            'command': command, 'use_cache': False, 'async_mode': True}).json()
        result = wait_for_task(task_client, submission['task_id'])
        assert result['status'] == 'completed'
        assert result['progress_percent'] == 100
        assert len(json.dumps(result)) < 16000
        handle = result['result']['stdout_artifact']['artifact_id']
        chunks, offset = [], 0
        while True:
            page = task_client.get(f'/api/artifacts/{handle}', params={'offset': offset, 'limit': 8192}).json()
            chunks.append(base64.b64decode(page['data']))
            if page['eof']:
                break
            offset = page['next_offset']
        assert b''.join(chunks) == b'x' * 100000 + b'\n'
        assert artifacts.artifact_path(handle).is_file()

    def test_cancel_identical_commands_targets_only_one_job(self, task_client):
        import shlex
        import sys

        command = shlex.join([sys.executable, '-u', '-c', 'import time; print("ready"); time.sleep(60)'])
        submissions = [task_client.post('/api/command', json={
            'command': command, 'use_cache': False, 'async_mode': True}).json() for _ in range(2)]
        ids = [result['task_id'] for result in submissions]
        assert ids[0] != ids[1]
        for task_id in ids:
            status = wait_for_task(task_client, task_id, lambda result: 'ready' in result.get('stdout_preview', ''))
            assert status['progress_percent'] is None
        response = task_client.delete(f'/api/tasks/{ids[0]}').json()
        assert response['cancel_requested'] is True
        assert wait_for_task(task_client, ids[0])['status'] == 'cancelled'
        assert task_client.get(f'/api/tasks/{ids[1]}').json()['status'] == 'running'
        task_client.delete(f'/api/tasks/{ids[1]}')
        assert wait_for_task(task_client, ids[1])['status'] == 'cancelled'
        assert not bear_server.active_processes

    def test_cancel_queued_job_does_not_run_and_queue_is_bounded(self, task_client, monkeypatch):
        import threading

        monkeypatch.setattr(bear_server, 'TASK_WORKERS', 1)
        monkeypatch.setattr(bear_server, 'MAX_PENDING_TASKS', 2)
        entered, release = threading.Event(), threading.Event()
        operation = MagicMock(return_value={'success': True})

        def block():
            entered.set()
            assert release.wait(10)
            return {'success': True}

        first = bear_server.submit_task(block, 'block')
        assert entered.wait(10)
        try:
            second = bear_server.submit_task(operation, 'queued')
            rejected = task_client.post('/api/command', json={'command': 'true', 'async_mode': True})
            assert rejected.status_code == 503
            task_client.delete(f'/api/tasks/{second["task_id"]}')
        finally:
            release.set()
        assert wait_for_task(task_client, first['task_id'])['status'] == 'completed'
        assert wait_for_task(task_client, second['task_id'])['status'] == 'cancelled'
        operation.assert_not_called()
        page = task_client.get('/api/tasks', params={'offset': 0, 'limit': 1}).json()
        assert len(page['tasks']) == 1
        assert page['total'] == 2 and page['next_offset'] == 1

    def test_failed_operation_and_expired_task_history(self, task_client, monkeypatch):
        monkeypatch.setattr(bear_server, 'MAX_TASKS', 1)
        operation = MagicMock(side_effect=ValueError('bad analysis'))
        first = bear_server.submit_task(operation, 'failure')
        result = wait_for_task(task_client, first['task_id'])
        assert result['status'] == 'failed' and result['result']['error'] == 'bad analysis'
        second = bear_server.submit_task(lambda: {'success': True}, 'success')
        assert wait_for_task(task_client, second['task_id'])['status'] == 'completed'
        assert task_client.get(f'/api/tasks/{first["task_id"]}').status_code == 404

    def test_python_has_prepared_analyzers_and_unique_script_files(self, task_client):
        script = 'from __future__ import annotations\nimport pefile, capstone\nprint(pefile.__name__, capstone.__name__)'
        submissions = [task_client.post('/api/python/execute', json={
            'script': script, 'filename': 'same.py', 'async_mode': True}).json() for _ in range(2)]
        results = [wait_for_task(task_client, item['task_id']) for item in submissions]
        assert all(item['status'] == 'completed' for item in results), results
        assert all(item['result']['stdout'].strip() == 'pefile capstone' for item in results)
        paths = [item['result']['command'][-1] for item in results]
        assert len(set(paths)) == 2
        assert not any(os.path.exists(path) for path in paths)

    @pytest.mark.parametrize('route', ['triage', 'strings'])
    def test_native_analysis_can_run_asynchronously(self, task_client, tmp_path, route):
        binary = tmp_path / 'raw'
        binary.write_bytes(b'hello\0world')
        params = {'binary' if route == 'triage' else 'file_path': str(binary), 'async_mode': True}
        response = task_client.post(f'/api/tools/{route}', json=params).json()
        status = wait_for_task(task_client, response['task_id'])
        assert status['status'] == 'completed'
        assert status['result']['success'] is True

    def test_python_rejects_path_components(self, task_client):
        for params in ({'env_name': '../outside'}, {'filename': '../outside.py'}):
            response = task_client.post('/api/python/execute', json={'script': 'pass', **params})
            assert response.status_code == 400


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
