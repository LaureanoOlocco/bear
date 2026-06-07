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
- Libc-Database - Libc identification and offset lookup
- Pwninit - Automate binary exploitation setup

Architecture: REST API backend for BEAR MCP client
Framework: FastAPI with enhanced command execution and caching
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
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from diskcache import Cache as DiskCache
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import psutil
import uvicorn

from bear.models import (
    BinwalkRequest,
    ChecksecRequest,
    FileCreateRequest,
    FileDeleteRequest,
    FileModifyRequest,
    GdbEnhancedRequest,
    GdbRequest,
    GhidraCallgraphRequest,
    GhidraFunctionsRequest,
    GenericCommandRequest,
    GhidraRequest,
    GhidraXrefsRequest,
    HexdumpRequest,
    LibcDatabaseRequest,
    ObjdumpRequest,
    OneGadgetRequest,
    PayloadGenerateRequest,
    PwntoolsRequest,
    PythonExecuteRequest,
    PythonInstallRequest,
    Radare2Request,
    ReadelfRequest,
    RopgadgetRequest,
    RopperRequest,
    PwninitRequest,
    StringsRequest,
    TriageRequest,
    XxdRequest,
)
from bear.ui import ModernVisualEngine

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
logging.getLogger('uvicorn.access').setLevel(logging.WARNING)

# FastAPI app configuration
app = FastAPI(title="BEAR", version="1.4.0")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return BEAR-style validation errors for API clients."""
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Map validation ValueErrors to HTTP 400."""
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Return BEAR-style error bodies for explicit HTTP errors."""
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc.detail)})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Return BEAR-style error bodies for unexpected server errors."""
    logger.error(f"Unhandled API error: {exc}")
    return JSONResponse(status_code=500, content={"error": f"Server error: {exc}"})

# API Configuration
API_PORT = int(os.environ.get('BEAR_PORT', 8888))
API_HOST = os.environ.get('BEAR_HOST', '127.0.0.1')
DEBUG_MODE = False
VERSION = "1.4.0"

# Command execution settings
COMMAND_TIMEOUT = int(os.environ.get('BEAR_TIMEOUT', 300))
CACHE_SIZE = int(os.environ.get('BEAR_CACHE_SIZE', 1000))
CACHE_TTL = int(os.environ.get('BEAR_CACHE_TTL', 3600))
CACHE_DIR = os.environ.get('BEAR_CACHE_DIR', '.bear_cache')
CACHE_SIZE_LIMIT = int(os.environ.get('BEAR_CACHE_SIZE_LIMIT', 1024 * 1024 * 1024))

# Global process management
active_processes: Dict[int, Dict[str, Any]] = {}
process_lock = threading.Lock()

# Async task tracking
task_results: Dict[str, Any] = {}
task_lock = threading.Lock()


def cleanup_temp_file(filepath):
    """Safely remove a temporary file"""
    if filepath and os.path.exists(filepath):
        try:
            os.remove(filepath)
        except:
            pass


# ============================================================================
# CACHING SYSTEM
# ============================================================================

class BearCache:
    """Persistent disk-backed cache for command results."""

    def __init__(self, directory: str = CACHE_DIR, max_size: int = CACHE_SIZE,
                 ttl: int = CACHE_TTL, size_limit: int = CACHE_SIZE_LIMIT):
        self.cache = DiskCache(directory, size_limit=size_limit)
        self.directory = directory
        self.max_size = max_size
        self.ttl = ttl
        self.lock = threading.Lock()
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def _fingerprint_file(self, path: str) -> Dict[str, Any]:
        if not path or not os.path.exists(path):
            return {"path": path, "exists": False}
        stat = os.stat(path)
        return {
            "path": os.path.abspath(path),
            "exists": True,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
        }

    def _normalize_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(params or {})
        fingerprints = {}
        for field in ("binary", "file_path", "libc_path", "libc", "ld", "script_file"):
            if field in normalized and normalized[field]:
                fingerprints[field] = self._fingerprint_file(str(normalized[field]))
        if fingerprints:
            normalized["_file_fingerprints"] = fingerprints
        return normalized

    def _generate_key(self, command: str, params: Dict[str, Any]) -> str:
        key_data = json.dumps({
            "command": command,
            "params": self._normalize_params(params),
        }, sort_keys=True, default=str)
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, command: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = self._generate_key(command, params)
        sentinel = object()
        data = self.cache.get(key, default=sentinel)
        with self.lock:
            if data is sentinel:
                self.stats["misses"] += 1
                return None
            self.stats["hits"] += 1
        return data

    def _enforce_entry_limit(self):
        while len(self.cache) > self.max_size:
            oldest_key = next(iter(self.cache.iterkeys()))
            self.cache.delete(oldest_key)
            with self.lock:
                self.stats["evictions"] += 1

    def set(self, command: str, params: Dict[str, Any], result: Dict[str, Any]):
        key = self._generate_key(command, params)
        self.cache.set(key, result, expire=self.ttl)
        self._enforce_entry_limit()

    def clear(self):
        self.cache.clear()
        with self.lock:
            self.stats = {"hits": 0, "misses": 0, "evictions": 0}

    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            stats = dict(self.stats)
        total = stats["hits"] + stats["misses"]
        hit_rate = (stats["hits"] / total * 100) if total > 0 else 0
        return {
            "backend": "diskcache",
            "directory": self.directory,
            "size": len(self.cache),
            "max_size": self.max_size,
            "size_limit_bytes": self.cache.size_limit,
            "volume_bytes": self.cache.volume(),
            "ttl_seconds": self.ttl,
            "hit_rate": f"{hit_rate:.1f}%",
            "hits": stats["hits"],
            "misses": stats["misses"],
            "evictions": stats["evictions"],
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
            if self.process is not None and self.process.stdout is not None:
                for line in iter(self.process.stdout.readline, ''):
                    if line:
                        self.stdout_data += line
        except Exception:
            pass

    def _read_stderr(self):
        try:
            if self.process is not None and self.process.stderr is not None:
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


def execute_command(command: str, use_cache: bool = True, timeout: int = COMMAND_TIMEOUT,
                    cache_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a shell command with caching support"""
    cache_params = cache_params or {}
    if use_cache:
        cached_result = cache.get(command, cache_params)
        if cached_result:
            return cached_result

    executor = EnhancedCommandExecutor(command, timeout)
    result = executor.execute()

    if use_cache and result.get("success", False):
        cache.set(command, cache_params, result)

    return result



def run_async_task(task_id: str, command: str, timeout: int, cleanup_file: Optional[str] = None) -> None:
    """Submit a command to run in a background thread and store result in task_results.

    Args:
        task_id: Unique identifier for this task
        command: Shell command to execute
        timeout: Execution timeout in seconds
        cleanup_file: Optional temp file to remove after execution
    """
    def _run():
        with task_lock:
            task_results[task_id]["status"] = "running"
            task_results[task_id]["started_at"] = time.time()

        result = execute_command(command, use_cache=False, timeout=timeout)

        if cleanup_file:
            cleanup_temp_file(cleanup_file)

        status = "completed" if result.get("success") else "failed"
        with task_lock:
            task_results[task_id].update({
                "status": status,
                "result": result,
                "completed_at": time.time(),
            })
        logger.info(f"[ASYNC] Task {task_id} {status} in {result.get('execution_time', 0):.1f}s")

    with task_lock:
        task_results[task_id] = {
            "task_id": task_id,
            "status": "queued",
            "submitted_at": time.time(),
            "started_at": None,
            "completed_at": None,
            "command": command,
            "result": None,
        }

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    logger.info(f"[ASYNC] Task {task_id} submitted")

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

@app.get("/health")
def health_check():
    """Health check endpoint"""
    logger.debug("Performing health check...")

    binary_tools = [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "one-gadget", "ropper", "pwninit", "strings",
        "xxd", "readelf", "hexdump"
    ]

    tools_status = {}
    for tool in binary_tools:
        logger.debug(f"Checking tool: {tool}")
        try:
            result = execute_command(f"which {tool}", use_cache=True)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    # Check Ghidra separately using find_ghidra_headless
    logger.debug("Checking tool: ghidra")
    tools_status["ghidra"] = find_ghidra_headless() is not None

    available_count = sum(1 for available in tools_status.values() if available)

    return {
        "status": "healthy",
        "message": "BEAR - Binary Exploitation & Automated Reversing Server is operational",
        "version": VERSION,
        "tools_status": tools_status,
        "total_tools_available": available_count,
        "total_tools_count": len(binary_tools),
        "cache_stats": cache.get_stats(),
        "telemetry": telemetry.get_stats(),
        "uptime": time.time() - telemetry.stats["start_time"]
    }


@app.post("/api/command")
def generic_command(params: GenericCommandRequest):
    """Execute any command"""
    try:
        return execute_command(params.command, params.use_cache)
    except Exception as e:
        logger.error(f"[API] /api/command - Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


# ============================================================================
# API ROUTES - FILE OPERATIONS
# ============================================================================

@app.post("/api/files/create")
def create_file(params: FileCreateRequest):
    return file_manager.create_file(params.filename, params.content, params.binary)


@app.post("/api/files/modify")
def modify_file(params: FileModifyRequest):
    return file_manager.modify_file(params.filename, params.content, params.append)


@app.post("/api/files/delete")
def delete_file(params: FileDeleteRequest):
    return file_manager.delete_file(params.filename)


@app.get("/api/files/list")
def list_files(directory: str = Query(".")):
    return file_manager.list_files(directory)


# ============================================================================
# API ROUTES - PAYLOAD GENERATION
# ============================================================================

@app.post("/api/payloads/generate")
def generate_payload(params: PayloadGenerateRequest):
    """Generate payloads for testing"""
    try:
        payload_type = params.type
        size = params.size
        pattern = params.pattern
        filename = params.filename or f"payload_{int(time.time())}.bin"

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
            import string
            import random
            content = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        else:
            content = pattern * size

        result = file_manager.create_file(filename, content)
        result["payload_type"] = payload_type
        result["payload_size"] = size
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")


# ============================================================================
# API ROUTES - CACHE & TELEMETRY
# ============================================================================

@app.get("/api/cache/stats")
def cache_stats():
    return cache.get_stats()


@app.post("/api/cache/clear")
def clear_cache():
    cache.clear()
    return {"success": True, "message": "Cache cleared"}


@app.get("/api/telemetry")
def get_telemetry():
    return telemetry.get_stats()


# ============================================================================
# API ROUTES - PROCESS MANAGEMENT
# ============================================================================

@app.get("/api/processes/list")
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
    return {
        "success": True,
        "total_count": len(process_list),
        "processes": process_list
    }


@app.get("/api/processes/status/{pid}")
def process_status(pid: int):
    status = ProcessManager.get_process_status(pid)
    if status:
        return {"success": True, "process": status}
    return JSONResponse(status_code=404, content={"success": False, "error": "Process not found"})


@app.post("/api/processes/terminate/{pid}")
def terminate_process(pid: int):
    success = ProcessManager.terminate_process(pid)
    return {"success": success}


@app.post("/api/processes/pause/{pid}")
def pause_process(pid: int):
    success = ProcessManager.pause_process(pid)
    return {"success": success}


@app.post("/api/processes/resume/{pid}")
def resume_process(pid: int):
    success = ProcessManager.resume_process(pid)
    return {"success": success}


@app.get("/api/processes/dashboard")
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
    return {
        "success": True,
        "total_processes": len(dashboard),
        "processes": dashboard
    }


# ============================================================================
# API ROUTES - PYTHON ENVIRONMENT
# ============================================================================

@app.post("/api/python/install")
def install_package(params: PythonInstallRequest):
    return python_env_manager.install_package(params.env_name, params.package)


@app.post("/api/python/execute")
def execute_script(params: PythonExecuteRequest):
    return python_env_manager.execute_script(params.env_name, params.script, params.filename)


# ============================================================================
# BINARY ANALYSIS TOOLS - CORE
# ============================================================================

@app.post("/api/tools/gdb")
def gdb(params: GdbRequest):
    """Execute GDB for binary analysis and debugging"""
    params = params.model_dump()
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
    result = execute_command(command, cache_params=params)
    cleanup_temp_file(temp_script)
    return result


@app.post("/api/tools/gdb-peda")
def gdb_peda(params: GdbEnhancedRequest):
    """Execute GDB with PEDA for enhanced debugging"""
    params = params.model_dump()
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

    result = execute_command(command, cache_params=params)
    cleanup_temp_file(temp_script)
    return result


@app.post("/api/tools/gdb-gef")
def gdb_gef(params: GdbEnhancedRequest):
    """Execute GDB with GEF for exploit development"""
    params = params.model_dump()
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

    result = execute_command(command, cache_params=params)
    cleanup_temp_file(temp_script)
    return result


@app.post("/api/tools/radare2")
def radare2(params: Radare2Request):
    """Execute Radare2 for binary analysis"""
    params = params.model_dump()
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

    result = execute_command(command, cache_params=params)
    cleanup_temp_file(temp_script)
    return result


@app.post("/api/tools/triage")
def triage_binary(params: TriageRequest):
    """Run a quick binary triage with common static-analysis commands."""
    params = params.model_dump()
    binary = params["binary"]
    strings_limit = params.get("strings_limit", 40)
    use_cache = params.get("use_cache", True)

    if not os.path.exists(binary):
        raise ValueError(f"Binary not found: {binary}")

    commands = {
        "file": f'file "{binary}"',
        "sha256": f'sha256sum "{binary}"',
        "checksec": f'checksec --file="{binary}"',
        "elf_header": f'readelf -h "{binary}"',
        "dynamic_symbols": f'readelf -Ws "{binary}"',
    }
    if strings_limit > 0:
        commands["strings"] = f'strings -n 4 "{binary}" | head -n {strings_limit}'

    results = {}
    for name, command in commands.items():
        results[name] = execute_command(command, use_cache=use_cache, cache_params=params)

    return {
        "success": True,
        "binary": binary,
        "checks": results,
        "summary": {
            "file": results.get("file", {}).get("stdout", "").strip(),
            "sha256": results.get("sha256", {}).get("stdout", "").split()[0] if results.get("sha256", {}).get("stdout") else "",
            "checksec_available": results.get("checksec", {}).get("success", False),
        },
    }


def build_ghidra_command(binary: str, function_name: str, script_name: str, project_prefix: str,
                         extra_args: Optional[list[str]] = None) -> str:
    """Build a Ghidra headless command for a BEAR script."""
    if not os.path.exists(binary):
        raise ValueError(f"Binary not found: {binary}")

    ghidra_headless = find_ghidra_headless()
    if not ghidra_headless:
        raise ValueError("Ghidra analyzeHeadless not found. Set GHIDRA_HEADLESS environment variable.")

    script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")

    if not os.path.exists(os.path.join(script_dir, script_name)):
        raise ValueError(f"Ghidra script not found: {script_dir}/{script_name}")

    project_dir = f"/tmp/ghidra_projects/{project_prefix}_{os.path.basename(binary)}_{int(time.time())}"
    os.makedirs(project_dir, exist_ok=True)

    script_args = [function_name] + list(extra_args or [])
    formatted_args = " ".join(f'"{arg}"' for arg in script_args)
    return f'"{ghidra_headless}" "{project_dir}" bear_project -import "{binary}" -scriptPath "{script_dir}" -postScript {script_name} {formatted_args} -deleteProject'


def extract_ghidra_json(stdout: str) -> Dict[str, Any]:
    """Extract JSON payload emitted by BEAR Ghidra scripts."""
    start_marker = "===BEAR_JSON_START==="
    end_marker = "===BEAR_JSON_END==="
    if start_marker not in stdout or end_marker not in stdout:
        raise ValueError("Ghidra output did not include BEAR JSON markers")

    json_start = stdout.index(start_marker) + len(start_marker)
    json_end = stdout.index(end_marker)
    json_str = stdout[json_start:json_end].strip()
    return json.loads(json_str)


def run_ghidra_inspection(params: Dict[str, Any], mode: str, extra_args: list[str]) -> Dict[str, Any]:
    """Run the shared Ghidra inspection script and parse its JSON output."""
    binary = params["binary"]
    analysis_timeout = params.get("timeout", 300)
    async_mode = params.get("async_mode", False)

    command = build_ghidra_command(binary, mode, "InspectBinary.java", mode, extra_args)

    if async_mode:
        task_id = f"ghidra_{mode}_{int(time.time() * 1000)}"
        run_async_task(task_id, command, analysis_timeout)
        return {
            "success": True,
            "async": True,
            "task_id": task_id,
            "status": "queued",
            "message": f"Ghidra {mode} inspection submitted. Poll GET /api/tasks/{task_id} for results.",
        }

    result = execute_command(command, timeout=analysis_timeout, cache_params=params)
    if result.get("success") and result.get("stdout"):
        try:
            inspected = extract_ghidra_json(result["stdout"])
            inspected["success"] = True
            inspected["mode"] = mode
            return inspected
        except (ValueError, json.JSONDecodeError) as e:
            return {
                "success": False,
                "error": f"Failed to parse Ghidra {mode} output: {str(e)}",
                "raw_output": result.get("stdout", ""),
            }

    return {
        "success": False,
        "error": f"Ghidra {mode} inspection failed or produced no output",
        "details": result,
    }


@app.post("/api/tools/ghidra/decompile")
def ghidra_decompile(params: GhidraRequest):
    """Decompile binary using Ghidra headless mode with custom script"""
    params = params.model_dump()
    binary = params["binary"]
    function_name = params.get("function", "all")
    analysis_timeout = params.get("timeout", 300)
    async_mode = params.get("async_mode", False)

    command = build_ghidra_command(binary, function_name, "DecompileFunction.java", "decompile")

    if async_mode:
        task_id = f"ghidra_{int(time.time() * 1000)}"
        run_async_task(task_id, command, analysis_timeout)
        return {
            "success": True,
            "async": True,
            "task_id": task_id,
            "status": "queued",
            "message": f"Ghidra decompilation submitted. Poll GET /api/tasks/{task_id} for results.",
        }

    result = execute_command(command, timeout=analysis_timeout, cache_params=params)

    if result.get("success") and result.get("stdout"):
        stdout = result["stdout"]
        try:
            decompiled = extract_ghidra_json(stdout)
            return {
                "success": True,
                "binary": binary,
                "function": function_name,
                "decompiled": decompiled
            }
        except (ValueError, json.JSONDecodeError) as e:
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


@app.post("/api/tools/ghidra/disassemble")
def ghidra_disassemble(params: GhidraRequest):
    """Disassemble binary using Ghidra headless mode with custom script"""
    params = params.model_dump()
    binary = params["binary"]
    function_name = params.get("function", "all")
    analysis_timeout = params.get("timeout", 300)
    async_mode = params.get("async_mode", False)

    command = build_ghidra_command(binary, function_name, "DisassembleFunction.java", "disassemble")

    if async_mode:
        task_id = f"ghidra_disassemble_{int(time.time() * 1000)}"
        run_async_task(task_id, command, analysis_timeout)
        return {
            "success": True,
            "async": True,
            "task_id": task_id,
            "status": "queued",
            "message": f"Ghidra disassembly submitted. Poll GET /api/tasks/{task_id} for results.",
        }

    result = execute_command(command, timeout=analysis_timeout, cache_params=params)

    if result.get("success") and result.get("stdout"):
        stdout = result["stdout"]
        try:
            disassembled = extract_ghidra_json(stdout)
            return {
                "success": True,
                "binary": binary,
                "function": function_name,
                "disassembled": disassembled
            }
        except (ValueError, json.JSONDecodeError) as e:
            return {
                "success": False,
                "error": f"Failed to parse disassembly output: {str(e)}",
                "raw_output": stdout
            }

    return {
        "success": False,
        "error": "Disassembly failed or produced no output",
        "details": result
    }


@app.post("/api/tools/ghidra/functions")
def ghidra_functions(params: GhidraFunctionsRequest):
    """List functions discovered by Ghidra."""
    params = params.model_dump()
    return run_ghidra_inspection(params, "functions", [])


@app.post("/api/tools/ghidra/xrefs")
def ghidra_xrefs(params: GhidraXrefsRequest):
    """Find references to/from a function, symbol, string, or address."""
    params = params.model_dump()
    return run_ghidra_inspection(
        params,
        "xrefs",
        [params["target"], params.get("direction", "both"), params.get("target_type", "auto")],
    )


@app.post("/api/tools/ghidra/callgraph")
def ghidra_callgraph(params: GhidraCallgraphRequest):
    """Build a Ghidra call graph for all functions or a selected root."""
    params = params.model_dump()
    return run_ghidra_inspection(
        params,
        "callgraph",
        [params.get("function", "all"), params.get("direction", "out"), str(params.get("depth", 2))],
    )


@app.post("/api/tools/binwalk")
def binwalk(params: BinwalkRequest):
    """Execute Binwalk for firmware analysis"""
    params = params.model_dump()
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
    return execute_command(command, cache_params=params)


# ============================================================================
# BINARY ANALYSIS TOOLS - INSPECTION
# ============================================================================

@app.post("/api/tools/checksec")
def checksec(params: ChecksecRequest):
    """Check security features of a binary"""
    params = params.model_dump()
    command = f"checksec --file={params['binary']}"
    return execute_command(command, use_cache=True, cache_params=params)


@app.post("/api/tools/strings")
def strings(params: StringsRequest):
    """Extract strings from a binary"""
    params = params.model_dump()
    min_len = params.get("min_len", 4)
    command = f"strings -n {min_len}"
    if params.get("encoding"):
        command += f" -e {params['encoding']}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['file_path']}"
    return execute_command(command, cache_params=params)


@app.post("/api/tools/objdump")
def objdump(params: ObjdumpRequest):
    """Analyze a binary using objdump"""
    params = params.model_dump()
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
    return execute_command(command, cache_params=params)


@app.post("/api/tools/readelf")
def readelf(params: ReadelfRequest):
    """Analyze ELF file headers and structure"""
    params = params.model_dump()
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
    return execute_command(command, cache_params=params)


@app.post("/api/tools/xxd")
def xxd(params: XxdRequest):
    """Create a hex dump using xxd"""
    params = params.model_dump()
    command = f"xxd -s {params.get('offset', '0')}"
    if params.get("length"):
        command += f" -l {params['length']}"
    command += f" -c {params.get('cols', 16)}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    command += f" {params['file_path']}"
    return execute_command(command, cache_params=params)


@app.post("/api/tools/hexdump")
def hexdump(params: HexdumpRequest):
    """Create a hex dump using hexdump"""
    params = params.model_dump()
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
    return execute_command(command, cache_params=params)


# ============================================================================
# BINARY ANALYSIS TOOLS - EXPLOIT DEVELOPMENT
# ============================================================================

@app.post("/api/tools/ropgadget")
def ropgadget(params: RopgadgetRequest):
    """Search for ROP gadgets using ROPgadget"""
    params = params.model_dump()
    command = f"ROPgadget --binary {params['binary']}"
    if params.get("gadget_type"):
        command += f" --only '{params['gadget_type']}'"
    if params.get("rop_chain"):
        command += " --ropchain"
    command += f" --depth {params.get('depth', 10)}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command, cache_params=params)


@app.post("/api/tools/ropper")
def ropper(params: RopperRequest):
    """Execute ropper for ROP/JOP gadget searching"""
    params = params.model_dump()
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
    return execute_command(command, cache_params=params)


@app.post("/api/tools/one-gadget")
def one_gadget(params: OneGadgetRequest):
    """Find one-shot RCE gadgets in libc"""
    params = params.model_dump()
    command = f"one_gadget {params['libc_path']} --level {params.get('level', 1)}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command, cache_params=params)


@app.post("/api/tools/pwntools")
def pwntools(params: PwntoolsRequest):
    """Execute Pwntools for exploit development"""
    params = params.model_dump()
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

    result = execute_command(command, cache_params=params)
    cleanup_temp_file(script_file)
    return result


@app.post("/api/tools/libc-database")
def libc_database(params: LibcDatabaseRequest):
    """Libc identification and offset lookup"""
    params = params.model_dump()
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

    return execute_command(command, cache_params=params)


@app.post("/api/tools/pwninit")
def pwninit(params: PwninitRequest):
    """CTF binary exploitation setup"""
    params = params.model_dump()
    command = f"pwninit --bin {params['binary']}"
    if params.get("libc"):
        command += f" --libc {params['libc']}"
    if params.get("ld"):
        command += f" --ld {params['ld']}"
    if params.get("template_type"):
        command += f" --template-type {params['template_type']}"
    if params.get("additional_args"):
        command += f" {params['additional_args']}"
    return execute_command(command, cache_params=params)


# ============================================================================
# API ROUTES - ASYNC TASKS
# ============================================================================

@app.get("/api/tasks")
def list_tasks():
    """List all async tasks and their current status"""
    with task_lock:
        tasks = []
        for task_id, info in task_results.items():
            entry = {
                "task_id": task_id,
                "status": info["status"],
                "submitted_at": info["submitted_at"],
                "started_at": info["started_at"],
                "completed_at": info["completed_at"],
                "command": info["command"],
            }
            if info["status"] == "running" and info["started_at"]:
                entry["runtime_seconds"] = round(time.time() - info["started_at"], 1)
            tasks.append(entry)
    return {"success": True, "total": len(tasks), "tasks": tasks}


@app.get("/api/tasks/{task_id}")
def get_task(task_id):
    """Get the status and result of a specific async task"""
    with task_lock:
        info = task_results.get(task_id)
    if info is None:
        return JSONResponse(status_code=404, content={"error": f"Task not found: {task_id}"})
    response = {
        "task_id": task_id,
        "status": info["status"],
        "submitted_at": info["submitted_at"],
        "started_at": info["started_at"],
        "completed_at": info["completed_at"],
    }
    if info["status"] == "running" and info["started_at"]:
        response["runtime_seconds"] = round(time.time() - info["started_at"], 1)
    if info["status"] in ("completed", "failed") and info["result"] is not None:
        response["result"] = info["result"]
    return response


@app.delete("/api/tasks/{task_id}")
def cancel_task(task_id):
    """Cancel a queued or running async task"""
    with task_lock:
        info = task_results.get(task_id)
    if info is None:
        return JSONResponse(status_code=404, content={"error": f"Task not found: {task_id}"})
    status = info["status"]
    if status in ("completed", "failed"):
        return JSONResponse(
            status_code=400,
            content={"success": False, "task_id": task_id, "error": f"Task already {status}, cannot cancel"},
        )
    cancelled = False
    with task_lock:
        processes_snapshot = dict(active_processes)
    command = info.get("command", "")
    for pid, proc_info in processes_snapshot.items():
        if proc_info.get("command") == command:
            cancelled = ProcessManager.terminate_process(pid)
            break
    with task_lock:
        if task_id in task_results:
            task_results[task_id]["status"] = "cancelled"
            task_results[task_id]["completed_at"] = time.time()
    logger.info(f"[ASYNC] Task {task_id} cancelled (process terminated: {cancelled})")
    return {"success": True, "task_id": task_id, "status": "cancelled", "process_terminated": cancelled}


# ============================================================================
# MAIN
# ============================================================================

BANNER = ModernVisualEngine.create_banner(VERSION)

def main():
    """Run the BEAR API server."""
    print(BANNER)

    parser = argparse.ArgumentParser(description="BEAR - Binary Exploitation & Automated Reversing Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port (default: {API_PORT})")
    args = parser.parse_args()

    debug_mode = DEBUG_MODE or args.debug
    port = args.port if args.port != API_PORT else API_PORT

    if debug_mode:
        logger.setLevel(logging.DEBUG)

    logger.info(f"Starting BEAR Server on port {port}")
    logger.info(f"Debug mode: {debug_mode}")
    logger.info(f"Cache size: {CACHE_SIZE} | TTL: {CACHE_TTL}s")
    logger.info(f"Cache directory: {CACHE_DIR}")
    logger.info(f"Command timeout: {COMMAND_TIMEOUT}s")

    uvicorn.run("bear.server:app", host="0.0.0.0", port=port, reload=debug_mode, log_level="debug" if debug_mode else "info")


if __name__ == "__main__":
    main()
