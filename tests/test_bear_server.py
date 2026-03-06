"""
BEAR Server Unit Tests
Tests for the BEAR API endpoints with mocked command execution
"""

import pytest
import json
import os
import sys
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bear_server import app


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_execute_command():
    """Mock the execute_command function"""
    with patch('bear_server.execute_command') as mock:
        yield mock


class TestHealthEndpoints:
    """Tests for health and status endpoints"""

    def test_health_check(self, client):
        """Test /health endpoint returns OK"""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'healthy'

    def test_cache_stats(self, client):
        """Test /api/cache/stats endpoint"""
        response = client.get('/api/cache/stats')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, dict)


class TestGhidraEndpoints:
    """Tests for Ghidra-related endpoints"""

    def test_ghidra_decompile_missing_binary(self, client):
        """Test ghidra/decompile endpoint returns error when binary is missing"""
        response = client.post('/api/tools/ghidra/decompile',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    def test_ghidra_decompile_binary_not_found(self, client):
        """Test ghidra/decompile returns error for non-existent binary"""
        response = client.post('/api/tools/ghidra/decompile',
                              json={'binary': '/nonexistent/binary'},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'not found' in data['error'].lower()

    @patch('bear_server.find_ghidra_headless')
    @patch('bear_server.execute_command')
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

        response = client.post('/api/tools/ghidra/decompile',
                              json={'binary': '/tmp/test', 'function': 'main'},
                              content_type='application/json')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'decompiled' in data
        assert len(data['decompiled']['functions']) == 1
        assert data['decompiled']['functions'][0]['name'] == 'main'


class TestGDBEndpoints:
    """Tests for GDB-related endpoints"""

    def test_gdb_missing_params(self, client):
        """Test gdb endpoint returns error when no params provided"""
        response = client.post('/api/tools/gdb',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_gdb_with_binary(self, mock_execute, client):
        """Test gdb with binary parameter"""
        mock_execute.return_value = {
            'success': True,
            'stdout': 'GNU gdb output',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/gdb',
                              json={'binary': '/bin/ls'},
                              content_type='application/json')
        assert response.status_code == 200
        mock_execute.assert_called_once()


class TestRadare2Endpoints:
    """Tests for Radare2-related endpoints"""

    def test_radare2_missing_binary(self, client):
        """Test radare2 endpoint returns error when binary is missing"""
        response = client.post('/api/tools/radare2',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
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

        response = client.post('/api/tools/radare2',
                              json={'binary': '/bin/ls', 'commands': 'aaa; afl'},
                              content_type='application/json')
        assert response.status_code == 200


class TestBinwalkEndpoints:
    """Tests for Binwalk-related endpoints"""

    def test_binwalk_missing_file(self, client):
        """Test binwalk endpoint returns error when file is missing"""
        response = client.post('/api/tools/binwalk',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_binwalk_basic(self, mock_execute, client):
        """Test basic binwalk analysis"""
        mock_execute.return_value = {
            'success': True,
            'stdout': 'DECIMAL       HEXADECIMAL     DESCRIPTION',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/binwalk',
                              json={'file_path': '/tmp/firmware.bin'},
                              content_type='application/json')
        assert response.status_code == 200


class TestChecksecEndpoints:
    """Tests for Checksec-related endpoints"""

    def test_checksec_missing_binary(self, client):
        """Test checksec endpoint returns error when binary is missing"""
        response = client.post('/api/tools/checksec',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_checksec_basic(self, mock_execute, client):
        """Test basic checksec"""
        mock_execute.return_value = {
            'success': True,
            'stdout': 'RELRO: Full RELRO\nStack: Canary found\nNX: NX enabled\nPIE: PIE enabled',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/checksec',
                              json={'binary': '/bin/ls'},
                              content_type='application/json')
        assert response.status_code == 200


class TestROPgadgetEndpoints:
    """Tests for ROPgadget-related endpoints"""

    def test_ropgadget_missing_binary(self, client):
        """Test ropgadget endpoint returns error when binary is missing"""
        response = client.post('/api/tools/ropgadget',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_ropgadget_basic(self, mock_execute, client):
        """Test basic ROPgadget search"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '0x0000000000401234 : pop rdi ; ret',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/ropgadget',
                              json={'binary': '/bin/ls'},
                              content_type='application/json')
        assert response.status_code == 200


class TestStringsEndpoints:
    """Tests for Strings-related endpoints"""

    def test_strings_missing_file(self, client):
        """Test strings endpoint returns error when file is missing"""
        response = client.post('/api/tools/strings',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_strings_basic(self, mock_execute, client):
        """Test basic strings extraction"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '/lib64/ld-linux-x86-64.so.2\nlibc.so.6\nputs',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/strings',
                              json={'file_path': '/bin/ls'},
                              content_type='application/json')
        assert response.status_code == 200


class TestObjdumpEndpoints:
    """Tests for Objdump-related endpoints"""

    def test_objdump_missing_binary(self, client):
        """Test objdump endpoint returns error when binary is missing"""
        response = client.post('/api/tools/objdump',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_objdump_disassemble(self, mock_execute, client):
        """Test objdump disassembly"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '0000000000401000 <main>:\n  401000: 55    push   %rbp',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/objdump',
                              json={'binary': '/bin/ls', 'disassemble': True},
                              content_type='application/json')
        assert response.status_code == 200


class TestOneGadgetEndpoints:
    """Tests for One-Gadget-related endpoints"""

    def test_one_gadget_missing_libc(self, client):
        """Test one-gadget endpoint returns error when libc_path is missing"""
        response = client.post('/api/tools/one-gadget',
                              json={},
                              content_type='application/json')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @patch('bear_server.execute_command')
    def test_one_gadget_basic(self, mock_execute, client):
        """Test basic one-gadget search"""
        mock_execute.return_value = {
            'success': True,
            'stdout': '0x4f2a5 execve("/bin/sh", rsp+0x40, environ)',
            'stderr': '',
            'return_code': 0
        }

        response = client.post('/api/tools/one-gadget',
                              json={'libc_path': '/lib/x86_64-linux-gnu/libc.so.6'},
                              content_type='application/json')
        assert response.status_code == 200



class TestAsyncTasks:
    """Tests for async task submission and polling endpoints"""

    def test_list_tasks_empty(self, client):
        """Test /api/tasks returns empty list when no tasks submitted"""
        import bear_server
        original = dict(bear_server.task_results)
        bear_server.task_results.clear()
        response = client.get('/api/tasks')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert data['total'] == 0
        assert data['tasks'] == []
        bear_server.task_results.update(original)

    def test_get_task_not_found(self, client):
        """Test GET /api/tasks/<task_id> returns 404 for unknown task"""
        response = client.get('/api/tasks/nonexistent_task_id')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data

    def test_cancel_task_not_found(self, client):
        """Test DELETE /api/tasks/<task_id> returns 404 for unknown task"""
        response = client.delete('/api/tasks/nonexistent_task_id')
        assert response.status_code == 404
        data = json.loads(response.data)
        assert 'error' in data

    def test_angr_async_submit(self, client):
        """Test angr with async_mode=True returns task_id immediately"""
        with patch('bear_server.run_async_task') as mock_async, \
             patch('os.path.exists', return_value=True), \
             patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_open.return_value.__exit__ = MagicMock(return_value=False)
            response = client.post('/api/tools/angr',
                                   json={'binary': '/bin/ls', 'async_mode': True},
                                   content_type='application/json')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True
            assert data['async'] is True
            assert 'task_id' in data
            assert data['status'] == 'queued'
            assert data['task_id'].startswith('angr_')
            mock_async.assert_called_once()

    def test_get_task_queued(self, client):
        """Test GET /api/tasks/<task_id> returns queued status"""
        import bear_server
        task_id = 'test_task_queued_123'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'queued',
            'submitted_at': 1000.0, 'started_at': None,
            'completed_at': None, 'command': 'python3 /tmp/test.py', 'result': None,
        }
        response = client.get(f'/api/tasks/{task_id}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['task_id'] == task_id
        assert data['status'] == 'queued'
        assert 'result' not in data
        del bear_server.task_results[task_id]

    def test_get_task_completed(self, client):
        """Test GET /api/tasks/<task_id> returns result when completed"""
        import bear_server
        task_id = 'test_task_done_456'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'completed',
            'submitted_at': 1000.0, 'started_at': 1001.0, 'completed_at': 1060.0,
            'command': 'python3 /tmp/angr_analysis.py',
            'result': {'success': True, 'stdout': 'done', 'execution_time': 59.0},
        }
        response = client.get(f'/api/tasks/{task_id}')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'completed'
        assert data['result']['success'] is True
        del bear_server.task_results[task_id]

    def test_cancel_completed_task_fails(self, client):
        """Test that cancelling a completed task returns 400"""
        import bear_server
        task_id = 'test_task_cancel_789'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'completed',
            'submitted_at': 1000.0, 'started_at': 1001.0, 'completed_at': 1060.0,
            'command': 'python3 /tmp/test.py', 'result': {'success': True},
        }
        response = client.delete(f'/api/tasks/{task_id}')
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        del bear_server.task_results[task_id]

    def test_list_tasks_with_entries(self, client):
        """Test /api/tasks lists all submitted tasks"""
        import bear_server
        task_id = 'test_list_task_abc'
        bear_server.task_results[task_id] = {
            'task_id': task_id, 'status': 'running',
            'submitted_at': 1000.0, 'started_at': 1001.0,
            'completed_at': None, 'command': 'python3 /tmp/angr.py', 'result': None,
        }
        response = client.get('/api/tasks')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        task_ids = [t['task_id'] for t in data['tasks']]
        assert task_id in task_ids
        del bear_server.task_results[task_id]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
