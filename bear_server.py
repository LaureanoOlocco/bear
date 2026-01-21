#!/usr/bin/env python3
"""
BEAR Server - Binary Exploitation & Automated Reversing Backend

Specialized for Binary Analysis & Reverse Engineering
Debuggers | Disassemblers | Exploit Development | Memory Forensics

TOOLS AVAILABLE (25+):
- GDB, GDB-PEDA, GDB-GEF - GNU Debugger with Python scripting and exploit development
- Radare2 - Advanced reverse engineering framework
- Ghidra - NSA's software reverse engineering suite (headless)
- Binwalk - Firmware analysis and extraction
- ROPgadget, Ropper - ROP/JOP gadget finders
- One-Gadget - Find one-shot RCE gadgets in libc
- Checksec - Binary security property checker
- Strings, Objdump, Readelf - Binary inspection tools
- XXD, Hexdump - Hex dump utilities
- Pwntools - CTF framework and exploit development library
- Angr - Binary analysis platform with symbolic execution
- Libc-Database - Libc identification and offset lookup
- Pwninit - Automate binary exploitation setup

Architecture: REST API backend for BEAR MCP client
Framework: Flask with enhanced command execution and caching
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
import hashlib
import shutil
import venv
import signal
from collections import OrderedDict
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from flask import Flask, request, jsonify
from functools import wraps
from schema import Schema, And, Optional as Opt, SchemaError
import psutil

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('bear.log')
        ]
    )
except PermissionError:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

logger = logging.getLogger(__name__)
logging.getLogger('werkzeug').setLevel(logging.WARNING)

# Flask app configuration
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# API Configuration
API_PORT = int(os.environ.get('BEAR_PORT', 8888))
API_HOST = os.environ.get('BEAR_HOST', '127.0.0.1')
DEBUG_MODE = False
VERSION = "1.3.0"

# Command execution settings
COMMAND_TIMEOUT = int(os.environ.get('BEAR_TIMEOUT', 300))
CACHE_SIZE = int(os.environ.get('BEAR_CACHE_SIZE', 1000))
CACHE_TTL = int(os.environ.get('BEAR_CACHE_TTL', 3600))

# Global process management
active_processes: Dict[int, Dict[str, Any]] = {}
process_lock = threading.Lock()


# ============================================================================
# SCHEMA VALIDATION & ENDPOINT DECORATOR
# ============================================================================

def tool_endpoint(schema, tool_name, use_cache=False):
    """Decorator for tool endpoints with schema validation and error handling"""
    def decorator(func):
        @wraps(func)
        def wrapper():
            try:
                params = schema.validate(request.json or {})
                target = params.get('binary', params.get('file_path', params.get('libc_path', 'input')))
                logger.info(f"Running {tool_name} on {target}")
                result = func(params)
                return jsonify(result)
            except SchemaError as e:
                logger.warning(f"[TOOL] {tool_name} - Validation error: {str(e)}")
                return jsonify({"error": str(e)}), 400
            except ValueError as e:
                logger.warning(f"[TOOL] {tool_name} - Validation error: {str(e)}")
                return jsonify({"error": str(e)}), 400
            except Exception as e:
                logger.error(f"[TOOL] {tool_name} - Error: {str(e)}")
                return jsonify({"error": f"Server error: {str(e)}"}), 500
        return wrapper
    return decorator


def cleanup_temp_file(filepath):
    """Safely remove a temporary file"""
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
        except:
            pass


# Tool Schemas
SCHEMAS = {
    "checksec": Schema({
        "binary": And(str, len)
    }),
    "strings": Schema({
        "file_path": And(str, len),
        Opt("min_len"): int,
        Opt("encoding"): str,
        Opt("additional_args"): str
    }),
    "objdump": Schema({
        "binary": And(str, len),
        Opt("disassemble"): bool,
        Opt("section"): str,
        Opt("additional_args"): str
    }),
    "readelf": Schema({
        "binary": And(str, len),
        Opt("headers"): bool,
        Opt("symbols"): bool,
        Opt("sections"): bool,
        Opt("all_info"): bool,
        Opt("additional_args"): str
    }),
    "xxd": Schema({
        "file_path": And(str, len),
        Opt("offset"): str,
        Opt("length"): str,
        Opt("cols"): int,
        Opt("reverse"): bool,
        Opt("additional_args"): str
    }),
    "hexdump": Schema({
        "file_path": And(str, len),
        Opt("format_type"): str,
        Opt("offset"): str,
        Opt("length"): str,
        Opt("additional_args"): str
    }),
    "binwalk": Schema({
        "file_path": And(str, len),
        Opt("extract"): bool,
        Opt("signature"): bool,
        Opt("entropy"): bool,
        Opt("additional_args"): str
    }),
    "ropgadget": Schema({
        "binary": And(str, len),
        Opt("gadget_type"): str,
        Opt("rop_chain"): bool,
        Opt("depth"): int,
        Opt("additional_args"): str
    }),
    "ropper": Schema({
        "binary": And(str, len),
        Opt("gadget_type"): str,
        Opt("quality"): int,
        Opt("arch"): str,
        Opt("search_string"): str,
        Opt("additional_args"): str
    }),
    "one_gadget": Schema({
        "libc_path": And(str, len),
        Opt("level"): int,
        Opt("additional_args"): str
    }),
    "gdb": Schema({
        "binary": And(str, len),
        Opt("commands"): str,
        Opt("script_file"): str,
        Opt("additional_args"): str
    }),
    "gdb_peda": Schema({
        Opt("binary"): str,
        Opt("commands"): str,
        Opt("attach_pid"): int,
        Opt("core_file"): str,
        Opt("additional_args"): str
    }),
    "gdb_gef": Schema({
        Opt("binary"): str,
        Opt("commands"): str,
        Opt("attach_pid"): int,
        Opt("core_file"): str,
        Opt("additional_args"): str
    }),
    "radare2": Schema({
        "binary": And(str, len),
        Opt("commands"): str,
        Opt("additional_args"): str
    }),
    "ghidra": Schema({
        "binary": And(str, len),
        Opt("function"): str,
        Opt("timeout"): int
    }),
    "pwntools": Schema({
        Opt("script_content"): str,
        Opt("target_binary"): str,
        Opt("target_host"): str,
        Opt("target_port"): int,
        Opt("exploit_type"): str,
        Opt("additional_args"): str
    }),
    "angr": Schema({
        "binary": And(str, len),
        Opt("script_content"): str,
        Opt("analysis_type"): str,
        Opt("find_address"): str,
        Opt("avoid_addresses"): str,
        Opt("additional_args"): str
    }),
    "libc_database": Schema({
        Opt("action"): str,
        Opt("symbols"): str,
        Opt("libc_id"): str,
        Opt("additional_args"): str
    }),
    "pwninit": Schema({
        "binary": And(str, len),
        Opt("libc"): str,
        Opt("ld"): str,
        Opt("template_type"): str,
        Opt("additional_args"): str
    }),
}


# ============================================================================
# VISUAL ENGINE
# ============================================================================

class ModernVisualEngine:
    """Visual output formatting for terminal display"""

    COLORS = {
        'MATRIX_GREEN': '\033[38;5;46m',
        'NEON_BLUE': '\033[38;5;51m',
        'ELECTRIC_PURPLE': '\033[38;5;129m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'HACKER_RED': '\033[38;5;196m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'BRIGHT_WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'BLOOD_RED': '\033[38;5;124m',
        'CRIMSON': '\033[38;5;160m',
    }

    PROGRESS_STYLES = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
    }

    @staticmethod
    def create_banner() -> str:
        """Create the BEAR banner"""
        accent = ModernVisualEngine.COLORS['HACKER_RED']
        RESET = ModernVisualEngine.COLORS['RESET']
        BOLD = ModernVisualEngine.COLORS['BOLD']
        return f"""
{accent}{BOLD}
██████╗ ███████╗ █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗  ███████║██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔══██╗
██████╔╝███████╗██║  ██║██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
{RESET}
{accent}┌─────────────────────────────────────────────────────────────────────────────┐
│  {ModernVisualEngine.COLORS['BRIGHT_WHITE']}Binary Exploitation & Automated Reversing{accent}                 v{VERSION}           │
│  {ModernVisualEngine.COLORS['CYBER_ORANGE']}Debuggers | Disassemblers | Exploit Development{accent}                            │
└─────────────────────────────────────────────────────────────────────────────┘{RESET}
"""

    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber',
                          label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a progress bar"""
        progress = max(0.0, min(1.0, progress))
        filled_width = int(width * progress)
        empty_width = width - filled_width
        bar = '█' * filled_width + '░' * empty_width
        percentage = f"{progress * 100:.1f}%"
        extra_info = f" ETA: {eta:.1f}s" if eta > 0 else ""
        if speed:
            extra_info += f" Speed: {speed}"
        if label:
            return f"{label}: [{bar}] {percentage}{extra_info}"
        return f"[{bar}] {percentage}{extra_info}"

    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "", progress: float = 0.0) -> str:
        """Format tool execution status"""
        color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if status == 'SUCCESS' else ModernVisualEngine.COLORS['HACKER_RED']
        return f"{color}🔧 {tool_name.upper()}{ModernVisualEngine.COLORS['RESET']} | {status} | {target}"


# ============================================================================
# CACHING SYSTEM
# ============================================================================

class BearCache:
    """Caching system for command results"""

    def __init__(self, max_size: int = CACHE_SIZE, ttl: int = CACHE_TTL):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.ttl = ttl
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        key_data = f"{command}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _is_expired(self, timestamp: float) -> bool:
        return time.time() - timestamp > self.ttl

    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = self._generate_key(command, params)
        if key in self.cache:
            timestamp, data = self.cache[key]
            if not self._is_expired(timestamp):
                self.cache.move_to_end(key)
                self.stats["hits"] += 1
                return data
            else:
                del self.cache[key]
        self.stats["misses"] += 1
        return None

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        key = self._generate_key(command, params)
        while len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            self.stats["evictions"] += 1
        self.cache[key] = (time.time(), result)

    def clear(self):
        self.cache.clear()
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def get_stats(self) -> Dict[str, Any]:
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "evictions": self.stats["evictions"]
        }


cache = BearCache()


# ============================================================================
# TELEMETRY COLLECTOR
# ============================================================================

class TelemetryCollector:
    """Collect system telemetry"""

    def __init__(self):
        self.stats = {
            "commands_executed": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
            "start_time": time.time()
        }

    def record_execution(self, success: bool, execution_time: float):
        self.stats["commands_executed"] += 1
        if success:
            self.stats["successful_commands"] += 1
        else:
            self.stats["failed_commands"] += 1
        self.stats["total_execution_time"] += execution_time

    def get_system_metrics(self) -> Dict[str, Any]:
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent
        }

    def get_stats(self) -> Dict[str, Any]:
        uptime = time.time() - self.stats["start_time"]
        total = self.stats["commands_executed"]
        success_rate = (self.stats["successful_commands"] / total * 100) if total > 0 else 0
        avg_time = (self.stats["total_execution_time"] / total) if total > 0 else 0
        return {
            "uptime_seconds": uptime,
            "commands_executed": total,
            "success_rate": f"{success_rate:.1f}%",
            "average_execution_time": f"{avg_time:.2f}s",
            "system_metrics": self.get_system_metrics()
        }


telemetry = TelemetryCollector()


# ============================================================================
# PROCESS MANAGER
# ============================================================================

class ProcessManager:
    """Process manager for command termination and monitoring"""

    @staticmethod
    def register_process(pid, command, process_obj):
        with process_lock:
            active_processes[pid] = {
                "pid": pid,
                "command": command,
                "process": process_obj,
                "start_time": time.time(),
                "status": "running",
                "progress": 0.0,
                "last_output": "",
                "bytes_processed": 0
            }

    @staticmethod
    def update_process_progress(pid, progress, last_output="", bytes_processed=0):
        with process_lock:
            if pid in active_processes:
                active_processes[pid]["progress"] = progress
                active_processes[pid]["last_output"] = last_output
                active_processes[pid]["bytes_processed"] = bytes_processed
                runtime = time.time() - active_processes[pid]["start_time"]
                active_processes[pid]["runtime"] = runtime
                if progress > 0:
                    active_processes[pid]["eta"] = (runtime / progress) * (1.0 - progress)

    @staticmethod
    def terminate_process(pid):
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        process_obj.terminate()
                        time.sleep(1)
                        if process_obj.poll() is None:
                            process_obj.kill()
                        active_processes[pid]["status"] = "terminated"
                        return True
                except Exception as e:
                    logger.error(f"Error terminating process {pid}: {e}")
            return False

    @staticmethod
    def cleanup_process(pid):
        with process_lock:
            if pid in active_processes:
                return active_processes.pop(pid)
            return None

    @staticmethod
    def get_process_status(pid):
        with process_lock:
            return active_processes.get(pid, None)

    @staticmethod
    def list_active_processes():
        with process_lock:
            return dict(active_processes)

    @staticmethod
    def pause_process(pid):
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGSTOP)
                        active_processes[pid]["status"] = "paused"
                        return True
                except Exception as e:
                    logger.error(f"Error pausing process {pid}: {e}")
            return False

    @staticmethod
    def resume_process(pid):
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.kill(pid, signal.SIGCONT)
                        active_processes[pid]["status"] = "running"
                        return True
                except Exception as e:
                    logger.error(f"Error resuming process {pid}: {e}")
            return False


# ============================================================================
# COMMAND EXECUTOR
# ============================================================================

class EnhancedCommandExecutor:
    """Enhanced command executor with progress tracking"""

    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.return_code = None
        self.start_time = None
        self.end_time = None

    def _read_stdout(self):
        try:
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.stdout_data += line
        except Exception:
            pass

    def _read_stderr(self):
        try:
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.stderr_data += line
        except Exception:
            pass

    def execute(self) -> Dict[str, Any]:
        self.start_time = time.time()

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            pid = self.process.pid
            ProcessManager.register_process(pid, self.command, self.process)

            stdout_thread = threading.Thread(target=self._read_stdout)
            stderr_thread = threading.Thread(target=self._read_stderr)
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.end_time = time.time()
                stdout_thread.join(timeout=1)
                stderr_thread.join(timeout=1)

                execution_time = self.end_time - self.start_time
                ProcessManager.cleanup_process(pid)
                success = self.return_code == 0
                telemetry.record_execution(success, execution_time)

                return {
                    "success": success,
                    "stdout": self.stdout_data,
                    "stderr": self.stderr_data,
                    "return_code": self.return_code,
                    "execution_time": execution_time,
                    "command": self.command
                }

            except subprocess.TimeoutExpired:
                self.process.kill()
                self.end_time = time.time()
                execution_time = self.end_time - self.start_time
                ProcessManager.cleanup_process(pid)
                telemetry.record_execution(False, execution_time)

                return {
                    "success": False,
                    "stdout": self.stdout_data,
                    "stderr": self.stderr_data + "\nCommand timed out",
                    "return_code": -1,
                    "execution_time": execution_time,
                    "timed_out": True,
                    "command": self.command
                }

        except Exception as e:
            self.end_time = time.time()
            execution_time = self.end_time - self.start_time if self.start_time else 0
            telemetry.record_execution(False, execution_time)
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "execution_time": execution_time,
                "error": str(e),
                "command": self.command
            }


def execute_command(command: str, use_cache: bool = True, timeout: int = COMMAND_TIMEOUT) -> Dict[str, Any]:
    """Execute a shell command with caching support"""
    if use_cache:
        cached_result = cache.get(command, {})
        if cached_result:
            return cached_result

    executor = EnhancedCommandExecutor(command, timeout)
    result = executor.execute()

    if use_cache and result.get("success", False):
        cache.set(command, {}, result)

    return result


# ============================================================================
# FILE OPERATIONS MANAGER
# ============================================================================

class FileOperationsManager:
    """Handle file operations"""

    def __init__(self, base_dir: str = "/tmp/bear_files"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.max_file_size = 100 * 1024 * 1024

    def create_file(self, filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        try:
            file_path = self.base_dir / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)
            if len(content.encode()) > self.max_file_size:
                return {"success": False, "error": f"File size exceeds {self.max_file_size} bytes"}
            mode = "wb" if binary else "w"
            with open(file_path, mode) as f:
                if binary:
                    f.write(content.encode() if isinstance(content, str) else content)
                else:
                    f.write(content)
            return {"success": True, "path": str(file_path), "size": len(content)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def modify_file(self, filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        try:
            file_path = self.base_dir / filename
            if not file_path.exists():
                return {"success": False, "error": "File does not exist"}
            mode = "a" if append else "w"
            with open(file_path, mode) as f:
                f.write(content)
            return {"success": True, "path": str(file_path)}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete_file(self, filename: str) -> Dict[str, Any]:
        try:
            file_path = self.base_dir / filename
            if not file_path.exists():
                return {"success": False, "error": "File does not exist"}
            if file_path.is_dir():
                shutil.rmtree(file_path)
            else:
                file_path.unlink()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def list_files(self, directory: str = ".") -> Dict[str, Any]:
        try:
            dir_path = self.base_dir / directory
            if not dir_path.exists():
                return {"success": False, "error": "Directory does not exist"}
            files = []
            for item in dir_path.iterdir():
                files.append({
                    "name": item.name,
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                    "modified": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
                })
            return {"success": True, "files": files}
        except Exception as e:
            return {"success": False, "error": str(e)}


file_manager = FileOperationsManager()


# ============================================================================
# PYTHON ENVIRONMENT MANAGER
# ============================================================================

class PythonEnvironmentManager:
    """Manage Python virtual environments"""

    def __init__(self, base_dir: str = "/tmp/bear_envs"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)

    def create_venv(self, env_name: str) -> Path:
        env_path = self.base_dir / env_name
        if not env_path.exists():
            venv.create(env_path, with_pip=True)
        return env_path

    def install_package(self, env_name: str, package: str) -> Dict[str, Any]:
        env_path = self.create_venv(env_name)
        pip_path = env_path / "bin" / "pip"
        try:
            result = subprocess.run(
                [str(pip_path), "install", package],
                capture_output=True,
                text=True,
                timeout=300
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def execute_script(self, env_name: str, script: str, filename: str = "") -> Dict[str, Any]:
        env_path = self.create_venv(env_name)
        python_path = env_path / "bin" / "python"
        script_file = self.base_dir / (filename or f"script_{int(time.time())}.py")
        try:
            with open(script_file, "w") as f:
                f.write(script)
            result = subprocess.run(
                [str(python_path), str(script_file)],
                capture_output=True,
                text=True,
                timeout=300
            )
            os.remove(script_file)
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except Exception as e:
            if script_file.exists():
                os.remove(script_file)
            return {"success": False, "error": str(e)}


python_env_manager = PythonEnvironmentManager()


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def find_ghidra_headless():
    """Find the analyzeHeadless script path"""
    import glob
    # Check common locations
    possible_paths = [
        shutil.which("analyzeHeadless"),
        os.environ.get("GHIDRA_HEADLESS"),
        os.path.expanduser("~/Documents/ghidra/ghidra_12.0_PUBLIC_20251205/ghidra_12.0_PUBLIC/support/analyzeHeadless"),
        "/opt/ghidra/support/analyzeHeadless",
        "/usr/local/ghidra/support/analyzeHeadless",
    ]

    for path in possible_paths:
        if path and os.path.exists(path):
            return path

    # Try to find it dynamically
    patterns = [
        os.path.expanduser("~/Documents/ghidra/*/*/support/analyzeHeadless"),
        os.path.expanduser("~/Documents/ghidra/*/support/analyzeHeadless"),
        os.path.expanduser("~/ghidra*/support/analyzeHeadless"),
        "/opt/ghidra*/support/analyzeHeadless",
        "/opt/ghidra/*/*/support/analyzeHeadless",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]

    return None


# ============================================================================
# API ROUTES - HEALTH & SYSTEM
# ============================================================================

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    logger.info("Performing health check...")

    binary_tools = [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "one-gadget", "ropper", "angr", "pwninit", "strings",
        "xxd", "readelf", "hexdump"
    ]

    tools_status = {}
    for tool in binary_tools:
        logger.info(f"Checking tool: {tool}")
        try:
            result = execute_command(f"which {tool}", use_cache=True)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    # Check Ghidra separately using find_ghidra_headless
    logger.info("Checking tool: ghidra")
    tools_status["ghidra"] = find_ghidra_headless() is not None

    available_count = sum(1 for available in tools_status.values() if available)

    return jsonify({
        "status": "healthy",
        "message": "BEAR - Binary Exploitation & Automated Reversing Server is operational",
        "version": VERSION,
        "tools_status": tools_status,
        "total_tools_available": available_count,
        "total_tools_count": len(binary_tools),
        "cache_stats": cache.get_stats(),
        "telemetry": telemetry.get_stats(),
        "uptime": time.time() - telemetry.stats["start_time"]
    })


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command"""
    try:
        params = request.json
        command = params.get("command", "")
        use_cache = params.get("use_cache", True)

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        result = execute_command(command, use_cache)
        return jsonify(result)
    except Exception as e:
        logger.error(f"[API] /api/command - Error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# API ROUTES - FILE OPERATIONS
# ============================================================================

@app.route("/api/files/create", methods=["POST"])
def create_file():
    params = request.json
    filename = params.get("filename", "")
    content = params.get("content", "")
    binary = params.get("binary", False)
    if not filename:
        return jsonify({"error": "Filename is required"}), 400
    result = file_manager.create_file(filename, content, binary)
    return jsonify(result)


@app.route("/api/files/modify", methods=["POST"])
def modify_file():
    params = request.json
    filename = params.get("filename", "")
    content = params.get("content", "")
    append = params.get("append", False)
    if not filename:
        return jsonify({"error": "Filename is required"}), 400
    result = file_manager.modify_file(filename, content, append)
    return jsonify(result)


@app.route("/api/files/delete", methods=["POST"])
def delete_file():
    params = request.json
    filename = params.get("filename", "")
    if not filename:
        return jsonify({"error": "Filename is required"}), 400
    result = file_manager.delete_file(filename)
    return jsonify(result)


@app.route("/api/files/list", methods=["GET"])
def list_files():
    directory = request.args.get("directory", ".")
    result = file_manager.list_files(directory)
    return jsonify(result)


# ============================================================================
# API ROUTES - PAYLOAD GENERATION
# ============================================================================

@app.route("/api/payloads/generate", methods=["POST"])
def generate_payload():
    """Generate payloads for testing"""
    try:
        params = request.json
        payload_type = params.get("type", "buffer")
        size = params.get("size", 1024)
        pattern = params.get("pattern", "A")
        filename = params.get("filename", f"payload_{int(time.time())}.bin")

        if payload_type == "buffer":
            content = pattern * size
        elif payload_type == "cyclic":
            # Generate cyclic pattern for offset detection
            import string
            chars = string.ascii_lowercase
            content = ""
            for i in range(size):
                content += chars[i % len(chars)]
        elif payload_type == "random":
            import random
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        else:
            content = pattern * size

        result = file_manager.create_file(filename, content)
        result["payload_type"] = payload_type
        result["payload_size"] = size
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# API ROUTES - CACHE & TELEMETRY
# ============================================================================

@app.route("/api/cache/stats", methods=["GET"])
def cache_stats():
    return jsonify(cache.get_stats())


@app.route("/api/cache/clear", methods=["POST"])
def clear_cache():
    cache.clear()
    return jsonify({"success": True, "message": "Cache cleared"})


@app.route("/api/telemetry", methods=["GET"])
def get_telemetry():
    return jsonify(telemetry.get_stats())


# ============================================================================
# API ROUTES - PROCESS MANAGEMENT
# ============================================================================

@app.route("/api/processes/list", methods=["GET"])
def list_processes():
    processes = ProcessManager.list_active_processes()
    process_list = []
    for pid, info in processes.items():
        process_list.append({
            "pid": pid,
            "command": info.get("command", "")[:100],
            "status": info.get("status", "unknown"),
            "runtime": info.get("runtime", 0),
            "progress": info.get("progress", 0)
        })
    return jsonify({
        "success": True,
        "total_count": len(process_list),
        "processes": process_list
    })


@app.route("/api/processes/status/<int:pid>", methods=["GET"])
def process_status(pid):
    status = ProcessManager.get_process_status(pid)
    if status:
        return jsonify({"success": True, "process": status})
    return jsonify({"success": False, "error": "Process not found"}), 404


@app.route("/api/processes/terminate/<int:pid>", methods=["POST"])
def terminate_process(pid):
    success = ProcessManager.terminate_process(pid)
    return jsonify({"success": success})


@app.route("/api/processes/pause/<int:pid>", methods=["POST"])
def pause_process(pid):
    success = ProcessManager.pause_process(pid)
    return jsonify({"success": success})


@app.route("/api/processes/resume/<int:pid>", methods=["POST"])
def resume_process(pid):
    success = ProcessManager.resume_process(pid)
    return jsonify({"success": success})


@app.route("/api/processes/dashboard", methods=["GET"])
def process_dashboard():
    processes = ProcessManager.list_active_processes()
    dashboard = []
    for pid, info in processes.items():
        progress = info.get("progress", 0)
        progress_bar = "█" * int(progress * 20) + "░" * (20 - int(progress * 20))
        dashboard.append({
            "pid": pid,
            "command": info.get("command", "")[:50],
            "status": info.get("status", "unknown"),
            "progress_bar": progress_bar,
            "progress_percent": f"{progress * 100:.1f}%",
            "runtime": f"{info.get('runtime', 0):.1f}s"
        })
    return jsonify({
        "success": True,
        "total_processes": len(dashboard),
        "processes": dashboard
    })


# ============================================================================
# API ROUTES - PYTHON ENVIRONMENT
# ============================================================================

@app.route("/api/python/install", methods=["POST"])
def install_package():
    params = request.json
    package = params.get("package", "")
    env_name = params.get("env_name", "default")
    if not package:
        return jsonify({"error": "Package name is required"}), 400
    result = python_env_manager.install_package(env_name, package)
    return jsonify(result)


@app.route("/api/python/execute", methods=["POST"])
def execute_script():
    params = request.json
    script = params.get("script", "")
    env_name = params.get("env_name", "default")
    filename = params.get("filename", "")
    if not script:
        return jsonify({"error": "Script content is required"}), 400
    result = python_env_manager.execute_script(env_name, script, filename)
    return jsonify(result)


# ============================================================================
# BINARY ANALYSIS TOOLS - CORE
# ============================================================================

@app.route("/api/tools/gdb", methods=["POST"])
@tool_endpoint(SCHEMAS["gdb"], "gdb")
def gdb(params):
    """Execute GDB for binary analysis and debugging"""
    temp_script = None
    command = f"gdb {params['binary']}"
    if params.get("script_file"):
        command += f" -x {params['script_file']}"
    if params.get("commands"):
        temp_script = "/tmp/gdb_commands.txt"
        with open(temp_script, "w") as f:
            f.write(params["commands"])
        command += f" -x {temp_script}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += " -batch"
    result = execute_command(command)
    cleanup_temp_file(temp_script)
    return result


@app.route("/api/tools/gdb-peda", methods=["POST"])
@tool_endpoint(SCHEMAS["gdb_peda"], "gdb-peda")
def gdb_peda(params):
    """Execute GDB with PEDA for enhanced debugging"""
    binary = params.get("binary", "")
    attach_pid = params.get("attach_pid", 0)
    core_file = params.get("core_file", "")
    if not binary and not attach_pid and not core_file:
        raise ValueError("Binary, PID, or core file is required")

    temp_script = None
    command = "gdb -q"
    if binary:
        command += f" {binary}"
    if core_file:
        command += f" {core_file}"
    if attach_pid:
        command += f" -p {attach_pid}"

    if params.get("commands"):
        temp_script = "/tmp/gdb_peda_commands.txt"
        peda_commands = f"source ~/peda/peda.py\n{params['commands']}\nquit"
        with open(temp_script, "w") as f:
            f.write(peda_commands)
        command += f" -x {temp_script}"
    else:
        command += " -ex 'source ~/peda/peda.py' -ex 'quit'"

    if params.get("additional_args"):
        command += f" {params['additional_args']}"

    result = execute_command(command)
    cleanup_temp_file(temp_script)
    return result


@app.route("/api/tools/gdb-gef", methods=["POST"])
@tool_endpoint(SCHEMAS["gdb_gef"], "gdb-gef")
def gdb_gef(params):
    """Execute GDB with GEF for exploit development"""
    binary = params.get("binary", "")
    attach_pid = params.get("attach_pid", 0)
    core_file = params.get("core_file", "")
    if not binary and not attach_pid and not core_file:
        raise ValueError("Binary, PID, or core file is required")

    temp_script = None
    command = "gdb -q"
    if binary:
        command += f" {binary}"
    if core_file:
        command += f" {core_file}"
    if attach_pid:
        command += f" -p {attach_pid}"

    if params.get("commands"):
        temp_script = "/tmp/gdb_gef_commands.txt"
        gef_commands = f"source ~/.gdbinit-gef.py\n{params['commands']}\nquit"
        with open(temp_script, "w") as f:
            f.write(gef_commands)
        command += f" -x {temp_script}"
    else:
        command += " -ex 'source ~/.gdbinit-gef.py' -ex 'quit'"

    if params.get("additional_args"):
        command += f" {params['additional_args']}"

    result = execute_command(command)
    cleanup_temp_file(temp_script)
    return result


@app.route("/api/tools/radare2", methods=["POST"])
@tool_endpoint(SCHEMAS["radare2"], "radare2")
def radare2(params):
    """Execute Radare2 for binary analysis"""
    temp_script = None
    if params.get("commands"):
        temp_script = "/tmp/r2_commands.txt"
        with open(temp_script, "w") as f:
            f.write(params["commands"])
        command = f"r2 -i {temp_script} -q {params['binary']}"
    else:
        command = f"r2 -q {params['binary']}"

    if params.get("additional_args"):
        command += f" {params['additional_args']}"

    result = execute_command(command)
    cleanup_temp_file(temp_script)
    return result


@app.route("/api/tools/ghidra/decompile", methods=["POST"])
@tool_endpoint(SCHEMAS["ghidra"], "ghidra")
def ghidra_decompile(params):
    """Decompile binary using Ghidra headless mode with custom script"""
    binary = params["binary"]
    function_name = params.get("function", "all")
    analysis_timeout = params.get("timeout", 300)

    if not os.path.exists(binary):
        raise ValueError(f"Binary not found: {binary}")

    ghidra_headless = find_ghidra_headless()
    if not ghidra_headless:
        raise ValueError("Ghidra analyzeHeadless not found. Set GHIDRA_HEADLESS environment variable.")

    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")
    decompile_script = "DecompileFunction.java"

    if not os.path.exists(os.path.join(script_dir, decompile_script)):
        raise ValueError(f"Decompile script not found: {script_dir}/{decompile_script}")

    project_dir = f"/tmp/ghidra_projects/decompile_{os.path.basename(binary)}_{int(time.time())}"
    os.makedirs(project_dir, exist_ok=True)

    command = f'"{ghidra_headless}" "{project_dir}" decompile_project -import "{binary}" -scriptPath "{script_dir}" -postScript {decompile_script} "{function_name}" -deleteProject'
    result = execute_command(command, timeout=analysis_timeout)

    if result.get("success") and result.get("stdout"):
        stdout = result["stdout"]
        start_marker = "===BEAR_JSON_START==="
        end_marker = "===BEAR_JSON_END==="

        if start_marker in stdout and end_marker in stdout:
            json_start = stdout.index(start_marker) + len(start_marker)
            json_end = stdout.index(end_marker)
            json_str = stdout[json_start:json_end].strip()

            try:
                decompiled = json.loads(json_str)
                return {
                    "success": True,
                    "binary": binary,
                    "function": function_name,
                    "decompiled": decompiled
                }
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"Failed to parse decompilation output: {str(e)}",
                    "raw_output": stdout
                }

    return {
        "success": False,
        "error": "Decompilation failed or produced no output",
        "details": result
    }


@app.route("/api/tools/binwalk", methods=["POST"])
@tool_endpoint(SCHEMAS["binwalk"], "binwalk")
def binwalk(params):
    """Execute Binwalk for firmware analysis"""
    command = "binwalk"
    if params.get("extract"):
        command += " -e"
    if params.get("signature"):
        command += " -B"
    if params.get("entropy"):
        command += " -E"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['file_path']}"
    return execute_command(command)


# ============================================================================
# BINARY ANALYSIS TOOLS - INSPECTION
# ============================================================================

@app.route("/api/tools/checksec", methods=["POST"])
@tool_endpoint(SCHEMAS["checksec"], "checksec")
def checksec(params):
    """Check security features of a binary"""
    command = f"checksec --file={params['binary']}"
    return execute_command(command, use_cache=True)


@app.route("/api/tools/strings", methods=["POST"])
@tool_endpoint(SCHEMAS["strings"], "strings")
def strings(params):
    """Extract strings from a binary"""
    min_len = params.get("min_len", 4)
    command = f"strings -n {min_len}"
    if params.get("encoding"):
        command += f" -e {params['encoding']}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['file_path']}"
    return execute_command(command)


@app.route("/api/tools/objdump", methods=["POST"])
@tool_endpoint(SCHEMAS["objdump"], "objdump")
def objdump(params):
    """Analyze a binary using objdump"""
    command = "objdump -M intel"
    if params.get("disassemble", True):
        command += " -d"
    else:
        command += " -x"
    if params.get("section"):
        command += f" -j {params['section']}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['binary']}"
    return execute_command(command)


@app.route("/api/tools/readelf", methods=["POST"])
@tool_endpoint(SCHEMAS["readelf"], "readelf")
def readelf(params):
    """Analyze ELF file headers and structure"""
    command = "readelf"
    if params.get("all_info"):
        command += " -a"
    else:
        if params.get("headers", True):
            command += " -h"
        if params.get("symbols"):
            command += " -s"
        if params.get("sections"):
            command += " -S"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['binary']}"
    return execute_command(command)


@app.route("/api/tools/xxd", methods=["POST"])
@tool_endpoint(SCHEMAS["xxd"], "xxd")
def xxd(params):
    """Create a hex dump using xxd"""
    command = f"xxd -s {params.get('offset', '0')}"
    if params.get("length"):
        command += f" -l {params['length']}"
    command += f" -c {params.get('cols', 16)}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['file_path']}"
    return execute_command(command)


@app.route("/api/tools/hexdump", methods=["POST"])
@tool_endpoint(SCHEMAS["hexdump"], "hexdump")
def hexdump(params):
    """Create a hex dump using hexdump"""
    format_type = params.get("format_type", "canonical")
    command = "hexdump"
    if format_type == "canonical":
        command += " -C"
    elif format_type == "one-byte-octal":
        command += " -b"
    elif format_type == "two-byte-decimal":
        command += " -d"
    offset = params.get("offset", "0")
    if offset != "0":
        command += f" -s {offset}"
    if params.get("length"):
        command += f" -n {params['length']}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['file_path']}"
    return execute_command(command)


# ============================================================================
# BINARY ANALYSIS TOOLS - EXPLOIT DEVELOPMENT
# ============================================================================

@app.route("/api/tools/ropgadget", methods=["POST"])
@tool_endpoint(SCHEMAS["ropgadget"], "ropgadget")
def ropgadget(params):
    """Search for ROP gadgets using ROPgadget"""
    command = f"ROPgadget --binary {params['binary']}"
    if params.get("gadget_type"):
        command += f" --only '{params['gadget_type']}'"
    if params.get("rop_chain"):
        command += " --ropchain"
    command += f" --depth {params.get('depth', 10)}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command)


@app.route("/api/tools/ropper", methods=["POST"])
@tool_endpoint(SCHEMAS["ropper"], "ropper")
def ropper(params):
    """Execute ropper for ROP/JOP gadget searching"""
    command = f"ropper --file {params['binary']}"
    gadget_type = params.get("gadget_type", "rop")
    if gadget_type == "rop":
        command += " --rop"
    elif gadget_type == "jop":
        command += " --jop"
    elif gadget_type == "sys":
        command += " --sys"
    elif gadget_type == "all":
        command += " --all"
    quality = params.get("quality", 1)
    if quality > 1:
        command += f" --quality {quality}"
    if params.get("arch"):
        command += f" --arch {params['arch']}"
    if params.get("search_string"):
        command += f" --search '{params['search_string']}'"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command)


@app.route("/api/tools/one-gadget", methods=["POST"])
@tool_endpoint(SCHEMAS["one_gadget"], "one-gadget")
def one_gadget(params):
    """Find one-shot RCE gadgets in libc"""
    command = f"one_gadget {params['libc_path']} --level {params.get('level', 1)}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command)


@app.route("/api/tools/pwntools", methods=["POST"])
@tool_endpoint(SCHEMAS["pwntools"], "pwntools")
def pwntools(params):
    """Execute Pwntools for exploit development"""
    script_content = params.get("script_content", "")
    target_binary = params.get("target_binary", "")
    target_host = params.get("target_host", "")
    target_port = params.get("target_port", 0)

    if not script_content and not target_binary:
        raise ValueError("Script content or target binary is required")

    script_file = "/tmp/pwntools_exploit.py"

    if script_content:
        with open(script_file, "w") as f:
            f.write(script_content)
    else:
        template = f"""#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

if binary:
    p = process(binary)
elif host and port:
    p = remote(host, port)
else:
    log.error("No target specified")
    exit(1)

p.interactive()
"""
        with open(script_file, "w") as f:
            f.write(template)

    command = f"python3 {script_file}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"

    result = execute_command(command)
    cleanup_temp_file(script_file)
    return result


@app.route("/api/tools/angr", methods=["POST"])
@tool_endpoint(SCHEMAS["angr"], "angr")
def angr(params):
    """Execute angr for symbolic execution"""
    binary = params["binary"]
    script_content = params.get("script_content", "")
    find_address = params.get("find_address", "")
    avoid_addresses = params.get("avoid_addresses", "")
    analysis_type = params.get("analysis_type", "symbolic")

    script_file = "/tmp/angr_analysis.py"

    if script_content:
        with open(script_file, "w") as f:
            f.write(script_content)
    else:
        template = f"""#!/usr/bin/env python3
import angr
import sys

project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")
"""
        if analysis_type == "symbolic" and find_address:
            template += f"""
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)
find_addr = {find_address}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else []}
simgr.explore(find=find_addr, avoid=avoid_addrs)
if simgr.found:
    print("Found solution!")
    solution_state = simgr.found[0]
    print(f"Input: {{solution_state.posix.dumps(0)}}")
else:
    print("No solution found")
"""
        elif analysis_type == "cfg":
            template += """
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")
for func_addr, func in list(cfg.functions.items())[:10]:
    print(f"Function: {func.name} at {hex(func_addr)}")
"""
        with open(script_file, "w") as f:
            f.write(template)

    command = f"python3 {script_file}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"

    result = execute_command(command, timeout=600)
    cleanup_temp_file(script_file)
    return result


@app.route("/api/tools/libc-database", methods=["POST"])
@tool_endpoint(SCHEMAS["libc_database"], "libc-database")
def libc_database(params):
    """Libc identification and offset lookup"""
    action = params.get("action", "find")
    symbols = params.get("symbols", "")
    libc_id = params.get("libc_id", "")

    if action == "find" and not symbols:
        raise ValueError("Symbols parameter is required for find action")
    if action in ["dump", "download"] and not libc_id:
        raise ValueError("libc_id parameter is required for dump/download actions")

    base_command = "cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null"

    if action == "find":
        command = f"{base_command} && ./find {symbols}"
    elif action == "dump":
        command = f"{base_command} && ./dump {libc_id}"
    elif action == "download":
        command = f"{base_command} && ./download {libc_id}"
    else:
        raise ValueError(f"Invalid action: {action}")

    if params.get("additional_args"):
        command += f" {params['additional_args']}"

    return execute_command(command)


@app.route("/api/tools/pwninit", methods=["POST"])
@tool_endpoint(SCHEMAS["pwninit"], "pwninit")
def pwninit(params):
    """CTF binary exploitation setup"""
    command = f"pwninit --bin {params['binary']}"
    if params.get("libc"):
        command += f" --libc {params['libc']}"
    if params.get("ld"):
        command += f" --ld {params['ld']}"
    if params.get("template_type"):
        command += f" --template-type {params['template_type']}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command)


# ============================================================================
# MAIN
# ============================================================================

BANNER = ModernVisualEngine.create_banner()

if __name__ == "__main__":
    print(BANNER)

    parser = argparse.ArgumentParser(description="BEAR - Binary Exploitation & Automated Reversing Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port (default: {API_PORT})")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    logger.info(f"Starting BEAR Server on port {API_PORT}")
    logger.info(f"Debug mode: {DEBUG_MODE}")
    logger.info(f"Cache size: {CACHE_SIZE} | TTL: {CACHE_TTL}s")
    logger.info(f"Command timeout: {COMMAND_TIMEOUT}s")

    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
