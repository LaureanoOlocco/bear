"""
BEAR Server Unit Tests
Tests for the BEAR API endpoints with mocked command execution
"""

import pytest
from unittest.mock import patch, MagicMock

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
    @patch('os.path.exists')
    def test_triage_binary_success(self, mock_exists, mock_execute, client):
        """Test successful binary triage"""
        mock_exists.return_value = True
        mock_execute.side_effect = [
            {'success': True, 'stdout': '/tmp/test: ELF 64-bit', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'abc123  /tmp/test', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'NX enabled', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'ELF Header', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'Symbol table', 'stderr': '', 'return_code': 0},
            {'success': True, 'stdout': 'hello\nworld', 'stderr': '', 'return_code': 0},
        ]

        response = client.post('/api/tools/triage', json={'binary': '/tmp/test'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['summary']['sha256'] == 'abc123'
        assert 'checksec' in data['checks']

    def test_triage_binary_missing_binary(self, client):
        """Test triage validation when binary is missing"""
        response = client.post('/api/tools/triage', json={})
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data


class TestGhidraEndpoints:
    """Tests for Ghidra-related endpoints"""

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

    @patch('bear.server.find_ghidra_headless')
    @patch('bear.server.execute_command')
    @patch('os.path.exists')
    @patch('os.makedirs')
    def test_ghidra_decompile_success(self, mock_makedirs, mock_exists,
                                       mock_execute, mock_find_ghidra, client):
        """Test successful ghidra decompilation"""
        mock_find_ghidra.return_value = '/opt/ghidra/support/analyzeHeadless'
        mock_exists.return_value = True
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
INFO Done''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/decompile', json={'binary': '/tmp/test', 'function': 'main'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert 'decompiled' in data
        assert len(data['decompiled']['functions']) == 1
        assert data['decompiled']['functions'][0]['name'] == 'main'

    @patch('bear.server.find_ghidra_headless')
    @patch('bear.server.execute_command')
    @patch('os.path.exists')
    @patch('os.makedirs')
    def test_ghidra_disassemble_success(self, mock_makedirs, mock_exists,
                                         mock_execute, mock_find_ghidra, client):
        """Test successful ghidra disassembly"""
        mock_find_ghidra.return_value = '/opt/ghidra/support/analyzeHeadless'
        mock_exists.return_value = True
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
INFO Done''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/disassemble', json={'binary': '/tmp/test', 'function': 'main'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] == True
        assert 'disassembled' in data
        assert len(data['disassembled']['functions']) == 1
        assert data['disassembled']['functions'][0]['instructions'][0]['mnemonic'] == 'PUSH'

    @patch('bear.server.find_ghidra_headless')
    @patch('bear.server.execute_command')
    @patch('os.path.exists')
    @patch('os.makedirs')
    def test_ghidra_functions_success(self, mock_makedirs, mock_exists,
                                      mock_execute, mock_find_ghidra, client):
        """Test successful ghidra function listing"""
        mock_find_ghidra.return_value = '/opt/ghidra/support/analyzeHeadless'
        mock_exists.return_value = True
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
INFO Done''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/functions', json={'binary': '/tmp/test'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['mode'] == 'functions'
        assert data['functions'][0]['name'] == 'main'

    @patch('bear.server.find_ghidra_headless')
    @patch('bear.server.execute_command')
    @patch('os.path.exists')
    @patch('os.makedirs')
    def test_ghidra_xrefs_success(self, mock_makedirs, mock_exists,
                                  mock_execute, mock_find_ghidra, client):
        """Test successful ghidra xrefs"""
        mock_find_ghidra.return_value = '/opt/ghidra/support/analyzeHeadless'
        mock_exists.return_value = True
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
INFO Done''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/xrefs', json={'binary': '/tmp/test', 'target': 'strcpy'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['mode'] == 'xrefs'
        assert data['xrefs_to'][0]['from_function'] == 'vuln'

    @patch('bear.server.find_ghidra_headless')
    @patch('bear.server.execute_command')
    @patch('os.path.exists')
    @patch('os.makedirs')
    def test_ghidra_callgraph_success(self, mock_makedirs, mock_exists,
                                      mock_execute, mock_find_ghidra, client):
        """Test successful ghidra callgraph"""
        mock_find_ghidra.return_value = '/opt/ghidra/support/analyzeHeadless'
        mock_exists.return_value = True
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
INFO Done''',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ghidra/callgraph', json={'binary': '/tmp/test', 'function': 'main'})
        assert response.status_code == 200
        data = response.json()
        assert data['success'] is True
        assert data['mode'] == 'callgraph'
        assert 'vuln' in data['callgraph']['main']


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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
