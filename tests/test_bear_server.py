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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
