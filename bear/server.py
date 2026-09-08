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
import asyncio
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
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
from bear.artifacts import BoundedJSONResponse, bounded_result, read_artifact
from bear.analysis import router as analysis_router
from bear.ghidra import DisassembleRequest

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

@asynccontextmanager
async def lifespan(app):
    global task_executor
    yield
    with task_lock:
        for info in task_results.values():
            if info["status"] in ("queued", "running"):
                info["cancel_requested"] = True
                info["_cancel_event"].set()
        executor, task_executor = task_executor, None
    if executor is not None:
        await asyncio.to_thread(executor.shutdown, wait=True)


app = FastAPI(title="BEAR", version="1.4.0", lifespan=lifespan,
              default_response_class=BoundedJSONResponse)
app.include_router(analysis_router)


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
task_context = threading.local()
task_executor = None
TASK_WORKERS = max(1, int(os.environ.get("BEAR_TASK_WORKERS", 4)))
MAX_TASKS = max(1, int(os.environ.get("BEAR_MAX_TASKS", 1000)))
MAX_PENDING_TASKS = max(1, int(os.environ.get("BEAR_MAX_PENDING_TASKS", 100)))
TASK_TTL = max(1, int(os.environ.get("BEAR_TASK_TTL", 86400)))


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
    """Process monitoring and control for subprocess sessions owned by BEAR."""

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
                "bytes_processed": 0,
                "task_id": getattr(task_context, "task_id", None),
                "progress_percent": None,
            }

    @staticmethod
    def update_process_progress(pid, progress, last_output="", bytes_processed=0):
        with process_lock:
            if pid in active_processes:
                active_processes[pid]["progress"] = progress if progress is not None else 0.0
                active_processes[pid]["progress_percent"] = progress * 100 if progress is not None else None
                active_processes[pid]["last_output"] = last_output[-4096:]
                active_processes[pid]["bytes_processed"] = bytes_processed
                runtime = time.time() - active_processes[pid]["start_time"]
                active_processes[pid]["runtime"] = runtime
                if progress is not None and progress > 0:
                    active_processes[pid]["eta"] = (runtime / progress) * (1.0 - progress)
                else:
                    active_processes[pid].pop("eta", None)

    @staticmethod
    def _terminate_process_group(process_obj):
        """Kill inherited descendants even if the session leader already exited."""
        try:
            os.killpg(process_obj.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process_obj.wait(timeout=0.2)
        except subprocess.TimeoutExpired:
            pass
        # The leader exiting does not imply that its descendants honored TERM.
        try:
            os.killpg(process_obj.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process_obj.wait()

    @staticmethod
    def terminate_process(pid):
        with process_lock:
            info = active_processes.get(pid)
        if info is None:
            return False
        try:
            ProcessManager._terminate_process_group(info["process"])
            with process_lock:
                if active_processes.get(pid) is info:
                    info["status"] = "terminated"
            return True
        except OSError:
            logger.exception("Error terminating process pid=%s", pid)
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
            info = active_processes.get(pid)
            return {key: value for key, value in info.items() if key != "process"} if info else None

    @staticmethod
    def list_active_processes():
        with process_lock:
            return {pid: {key: value for key, value in info.items() if key != "process"}
                    for pid, info in active_processes.items()}

    @staticmethod
    def pause_process(pid):
        with process_lock:
            if pid in active_processes:
                try:
                    process_obj = active_processes[pid]["process"]
                    if process_obj and process_obj.poll() is None:
                        os.killpg(pid, signal.SIGSTOP)
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
                        os.killpg(pid, signal.SIGCONT)
                        active_processes[pid]["status"] = "running"
                        return True
                except Exception as e:
                    logger.error(f"Error resuming process {pid}: {e}")
            return False


# ============================================================================
# COMMAND EXECUTOR
# ============================================================================

class EnhancedCommandExecutor:
    """Drain binary pipes to disk, retaining only fixed-size previews in memory."""

    def __init__(self, command: str | list[str], timeout: int = COMMAND_TIMEOUT,
                 max_output_bytes: Optional[int] = None):
        from bear.artifacts import DEFAULT_MAX_OUTPUT_BYTES

        self.command = command
        self.timeout = timeout
        self.max_output_bytes = (int(os.environ.get("BEAR_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT_BYTES))
                                 if max_output_bytes is None else max_output_bytes)
        if type(self.max_output_bytes) is not int or self.max_output_bytes < 0:
            raise ValueError("max_output_bytes must be a nonnegative integer")
        self.process = None
        self.return_code = None
        self.start_time = None
        self.end_time = None

    def execute(self) -> Dict[str, Any]:
        import selectors
        import tempfile
        from contextlib import ExitStack
        from bear.artifacts import COPY_CHUNK_BYTES, PREVIEW_BYTES, store_file

        self.start_time = time.monotonic()
        success = False
        finished = False
        output_bytes = 0
        timed_out = False
        output_limit_exceeded = False
        drain_deadline = None
        output_incomplete = False
        try:
            check_task_cancelled()
            with ExitStack() as stack:
                selector = stack.enter_context(selectors.DefaultSelector())
                streams = {
                    name: {"file": stack.enter_context(tempfile.NamedTemporaryFile(mode="w+b")),
                           "preview": bytearray(), "size": 0}
                    for name in ("stdout", "stderr")
                }
                self.process = subprocess.Popen(
                    self.command,
                    shell=isinstance(self.command, str),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    bufsize=0,
                )
                pid = self.process.pid
                ProcessManager.register_process(pid, self.command, self.process)
                for name in streams:
                    pipe = getattr(self.process, name)
                    stack.callback(pipe.close)
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)

                next_progress = 0.0
                while selector.get_map() or self.process.poll() is None:
                    check_task_cancelled()
                    now = time.monotonic()
                    if not timed_out and not output_limit_exceeded and now - self.start_time >= self.timeout:
                        timed_out = True
                        ProcessManager._terminate_process_group(self.process)
                        drain_deadline = time.monotonic() + 0.5
                    # Detached descendants may retain pipes outside our process
                    # group. Do not let their missing EOF defeat a timeout/limit.
                    if drain_deadline is not None and now >= drain_deadline:
                        output_incomplete = bool(selector.get_map())
                        break
                    if now >= next_progress:
                        previews = {f"{name}_preview": bytes(stream["preview"]).decode("utf-8", "replace")
                                    for name, stream in streams.items()}
                        update_task_progress(stage="executing", progress_percent=None,
                                             output_bytes=output_bytes, **previews)
                        ProcessManager.update_process_progress(
                            pid, None, previews["stdout_preview"] or previews["stderr_preview"], output_bytes)
                        next_progress = now + 0.1
                    for key, _ in selector.select(timeout=0.1):
                        check_task_cancelled()
                        try:
                            chunk = os.read(key.fd, COPY_CHUNK_BYTES)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        stream = streams[key.data]
                        remaining = self.max_output_bytes - output_bytes
                        captured = chunk[:remaining]
                        if captured:
                            stream["file"].write(captured)
                            stream["size"] += len(captured)
                            output_bytes += len(captured)
                            stream["preview"].extend(captured[:max(0, PREVIEW_BYTES - len(stream["preview"]))])
                        if len(chunk) > remaining and not output_limit_exceeded:
                            output_limit_exceeded = True
                            ProcessManager._terminate_process_group(self.process)
                            drain_deadline = time.monotonic() + 0.5

                self.return_code = self.process.wait()
                check_task_cancelled()
                result = {
                    "success": self.return_code == 0 and not timed_out and not output_limit_exceeded,
                    "return_code": self.return_code,
                    "timed_out": timed_out,
                    "output_limit_exceeded": output_limit_exceeded,
                    "output_incomplete": output_incomplete,
                    "output_bytes": output_bytes,
                    "command": self.command,
                }
                if output_limit_exceeded:
                    result["error"] = "output_limit_exceeded"
                elif timed_out:
                    result["error"] = "Command timed out"
                for name, stream in streams.items():
                    preview = bytes(stream["preview"])
                    result[name] = preview.decode("utf-8", "replace")
                    try:
                        preview.decode("utf-8")
                        invalid_utf8 = False
                    except UnicodeDecodeError:
                        invalid_utf8 = True
                    truncated = stream["size"] > len(preview) or output_limit_exceeded or output_incomplete
                    result[f"{name}_truncated"] = truncated
                    if stream["size"] and (truncated or invalid_utf8):
                        stream["file"].flush()
                        result[f"{name}_artifact"] = store_file(stream["file"].name)
                update_task_progress(stage="executing", progress_percent=None, output_bytes=output_bytes,
                                     stdout_preview=result["stdout"], stderr_preview=result["stderr"])
            check_task_cancelled()
            result["execution_time"] = time.monotonic() - self.start_time
            success = result["success"]
            finished = True
            return result
        except TaskCancelled:
            raise
        except Exception as exc:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(exc)[:4096],
                "return_code": -1,
                "execution_time": time.monotonic() - self.start_time,
                "timed_out": timed_out,
                "output_limit_exceeded": output_limit_exceeded,
                "output_bytes": output_bytes,
                "error": str(exc)[:4096],
                "command": self.command,
            }
        finally:
            try:
                if self.process is not None and not finished:
                    ProcessManager._terminate_process_group(self.process)
            finally:
                if self.process is not None:
                    ProcessManager.cleanup_process(self.process.pid)
                    for name in ("stdout", "stderr"):
                        pipe = getattr(self.process, name)
                        if pipe is not None:
                            pipe.close()
                self.end_time = time.monotonic()
                telemetry.record_execution(success, self.end_time - self.start_time)


def execute_command(command: str | list[str], use_cache: bool = True, timeout: int = COMMAND_TIMEOUT,
                    cache_params: Optional[Dict[str, Any]] = None,
                    max_output_bytes: Optional[int] = None) -> Dict[str, Any]:
    """Run shell strings or shell-free argv lists, caching only successful captures."""
    check_task_cancelled()
    executor = EnhancedCommandExecutor(command, timeout, max_output_bytes=max_output_bytes)
    # Exclude persisted pre-artifact results and results made with different limits.
    cache_params = {**(cache_params or {}), "_bounded_output_version": 1,
                    "_timeout": timeout, "_max_output_bytes": executor.max_output_bytes}
    if use_cache:
        cached_result = cache.get(command, cache_params)
        if cached_result:
            check_task_cancelled()
            logger.info("Command cache=hit return_code=%s timed_out=%s execution_time=%s",
                        cached_result.get("return_code"), cached_result.get("timed_out", False),
                        cached_result.get("execution_time"))
            return cached_result

    result = executor.execute()
    check_task_cancelled()

    if use_cache and result.get("success", False):
        cache.set(command, cache_params, result)

    logger.info("Command cache=%s return_code=%s timed_out=%s execution_time=%s output_bytes=%s",
                "miss" if use_cache else "disabled", result.get("return_code"),
                result.get("timed_out", False), result.get("execution_time"), result.get("output_bytes"))
    return result



class TaskCancelled(Exception):
    """Cooperative cancellation, raised only on the thread owning a task."""


def check_task_cancelled():
    event = getattr(task_context, "cancel_event", None)
    if event is not None and event.is_set():
        raise TaskCancelled()


def update_task_progress(**fields):
    task_id = getattr(task_context, "task_id", None)
    if task_id is None:
        return
    check_task_cancelled()
    # Bound partial results before keeping them in the in-memory task registry.
    if "partial_results" in fields:
        partial = bounded_result(fields["partial_results"])
        if isinstance(partial, dict) and partial.get("truncated"):
            fields["partial_results"] = []
            fields["partial_results_artifact"] = partial["artifact"]
        else:
            fields["partial_results"] = partial
    with task_lock:
        info = task_results[task_id]
        if info["status"] == "running":
            info.update(fields, updated_at=time.time())


def submit_task(operation, label: str) -> dict:
    """Bound queue/history size and associate cancellation with a task, not a command."""
    global task_executor
    task_id = uuid.uuid4().hex
    event = threading.Event()

    def run():
        task_context.task_id = task_id
        task_context.cancel_event = event
        status, result = "failed", None
        try:
            check_task_cancelled()
            with task_lock:
                task_results[task_id].update(status="running", started_at=time.time())
            result = bounded_result(operation())
            check_task_cancelled()
            status = "completed" if result.get("success") else "failed"
        except TaskCancelled:
            status = "cancelled"
        except Exception as exc:
            logger.exception("Task %s (%s) failed", task_id, label)
            result = {"success": False, "error": str(exc)[:4096]}
        finally:
            with task_lock:
                # A cancellation racing with completion must not be overwritten.
                if event.is_set():
                    status, result = "cancelled", None
                info = task_results[task_id]
                info.update(status=status, stage=status, result=result, completed_at=time.time())
                if status == "completed":
                    info["progress_percent"] = 100.0
                info.pop("_cancel_event", None)
            task_context.__dict__.clear()
            logger.info("Task task_id=%s operation=%s status=%s", task_id, label, status)

    with task_lock:
        now = time.time()
        finished = sorted((key for key, info in task_results.items()
                           if info["status"] in ("completed", "failed", "cancelled")),
                          key=lambda key: task_results[key]["completed_at"] or 0)
        for key in finished:
            if len(task_results) >= MAX_TASKS or now - (task_results[key]["completed_at"] or 0) > TASK_TTL:
                del task_results[key]
        active = sum(info["status"] in ("queued", "running") for info in task_results.values())
        if active >= MAX_PENDING_TASKS or len(task_results) >= MAX_TASKS:
            raise HTTPException(503, "Task queue is full; wait for existing tasks to finish")
        task_results[task_id] = {
            "task_id": task_id, "status": "queued", "stage": "queued", "command": label,
            "submitted_at": now, "started_at": None, "completed_at": None,
            "result": None, "progress_percent": None, "cancel_requested": False,
            "_cancel_event": event,
        }
        if task_executor is None:
            task_executor = ThreadPoolExecutor(max_workers=TASK_WORKERS, thread_name_prefix="bear-task")
        try:
            task_executor.submit(run)
        except Exception:
            del task_results[task_id]
            raise
    return {"success": True, "async": True, "task_id": task_id, "status": "queued",
            "message": f"Poll GET /api/tasks/{task_id} for progress and results"}

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
        self.lock = threading.Lock()

    def create_venv(self, env_name: str) -> Path:
        if not env_name or Path(env_name).name != env_name or env_name in (".", ".."):
            raise ValueError("env_name must be a single directory name")
        env_path = self.base_dir / env_name
        with self.lock:
            if not (env_path / "pyvenv.cfg").is_file():
                venv.create(env_path, with_pip=True)
        return env_path

    def install_package(self, env_name: str, package: str) -> Dict[str, Any]:
        env_path = self.create_venv(env_name)
        pip_path = env_path / "bin" / "pip"
        return execute_command([str(pip_path), "install", "--", package], use_cache=False)

    def execute_script(self, env_name: str, script: str, filename: str = "",
                       timeout: int = COMMAND_TIMEOUT) -> Dict[str, Any]:
        env_path = self.create_venv(env_name)
        python_path = env_path / "bin" / "python"
        if filename and (Path(filename).name != filename or filename in (".", "..")):
            raise ValueError("filename must be a basename")
        with tempfile.TemporaryDirectory(prefix="script-", dir=self.base_dir) as directory:
            script_file = Path(directory) / (filename or "analysis.py")
            script_file.write_text(script, encoding="utf-8")
            # Keep previously installed per-environment packages. Add BEAR's
            # bundled analyzers as a fallback, rather than downloading per job.
            import sysconfig
            libraries = list(dict.fromkeys([sysconfig.get_path("purelib"), sysconfig.get_path("platlib")]))
            bootstrap = (f"import runpy,sys; sys.path.extend({libraries!r}); "
                         "runpy.run_path(sys.argv[1], run_name='__main__')")
            return execute_command([str(python_path), "-u", "-c", bootstrap, str(script_file)],
                                   use_cache=False, timeout=timeout)


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
        os.path.expanduser("~/Ghidra/*/support/analyzeHeadless"),
        os.path.expanduser("~/ghidra/*/support/analyzeHeadless"),
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
    if params.async_mode:
        return submit_task(lambda: execute_command(params.command, params.use_cache, params.timeout), "command")
    try:
        return execute_command(params.command, params.use_cache, params.timeout)
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
    if params.async_mode:
        return submit_task(lambda: execute_script(params.model_copy(update={"async_mode": False})), "python")
    return python_env_manager.execute_script(params.env_name, params.script, params.filename, params.timeout)


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
    """Format-aware triage with opt-in whole-file work."""
    from bear.analysis import triage

    if params.async_mode:
        return submit_task(lambda: triage_binary(params.model_copy(update={"async_mode": False})), "triage")
    result = triage(params.model_dump(), execute_command, check_task_cancelled)
    logger.info("Triage format=%s success=%s partial=%s", result["format"], result["success"], result["partial"])
    return result


def build_ghidra_command(binary: str, function_name: str, script_name: str,
                         project_dir: Path, ghidra_headless: str, reuse: bool = False,
                         extra_args: Optional[list[str]] = None) -> str:
    """Build safely quoted argv for an already locked project."""
    from bear.ghidra import build_command

    return build_command(ghidra_headless, str(Path(binary).resolve()), project_dir,
                         reuse, script_name, [function_name, *(extra_args or [])])


def extract_ghidra_json(stdout: str) -> Dict[str, Any]:
    """Extract JSON payload emitted by BEAR Ghidra scripts."""
    start_marker = "===BEAR_JSON_START==="
    end_marker = "===BEAR_JSON_END==="
    if start_marker not in stdout or end_marker not in stdout:
        raise ValueError("Ghidra output did not include BEAR JSON markers")

    json_start = stdout.index(start_marker) + len(start_marker)
    json_str = stdout[json_start:].lstrip()
    payload, json_end = json.JSONDecoder().raw_decode(json_str)
    if not isinstance(payload, dict) or not json_str[json_end:].lstrip().startswith(end_marker):
        raise ValueError("Ghidra output did not contain a complete BEAR JSON object")
    return payload


def run_ghidra(params: Dict[str, Any], mode: str, script_name: str,
               script_target: str, extra_args: Optional[list[str]] = None) -> Dict[str, Any]:
    """Use the same locked, parsed pipeline for synchronous and asynchronous calls."""
    from bear.ghidra import run_project

    binary = params["binary"]
    if not Path(binary).is_file():
        raise ValueError(f"Binary not found: {binary}")
    headless = find_ghidra_headless()
    if not headless:
        raise ValueError("Ghidra analyzeHeadless not found. Set GHIDRA_HEADLESS environment variable.")
    if params.get("async_mode", False):
        return submit_task(
            lambda: run_ghidra({**params, "async_mode": False}, mode, script_name, script_target, extra_args),
            label=f"ghidra_{mode}",
        )
    analysis_binary = str(Path(binary).resolve())
    headless = str(Path(headless).resolve())

    def inspect(project: Path, reuse: bool) -> Dict[str, Any]:
        command = build_ghidra_command(analysis_binary, script_target, script_name, project,
                                       headless, reuse, extra_args)
        result = execute_command(command, use_cache=False, timeout=params.get("timeout", 300))
        check_task_cancelled()
        if (not result.get("success") or result.get("timed_out") or result.get("cancelled")
                or result.get("return_code", 0) != 0):
            return {"success": False, "error": f"Ghidra {mode} failed or produced no output", "details": result}
        update_task_progress(stage="parsing")
        try:
            stdout = result.get("stdout", "")
            if result.get("stdout_artifact"):
                from bear.artifacts import artifact_path

                stdout = Path(artifact_path(result["stdout_artifact"]["artifact_id"])).read_text(
                    encoding="utf-8", errors="replace")
            inspected = extract_ghidra_json(stdout)
            # Headless may exit zero after a failed import/save. Script JSON is
            # emitted before saving, so it alone cannot certify a reusable project.
            completion = stdout.rpartition("===BEAR_JSON_END===")[2]
            if ("REPORT: Save succeeded" not in completion
                    or (not reuse and "REPORT: Import succeeded" not in completion)):
                raise ValueError("Ghidra did not confirm successful project save/import")
        except (ValueError, OSError, KeyError) as e:
            failure = {
                "success": False,
                "error": f"Failed to parse Ghidra {mode} output: {str(e)}",
                "raw_output": result.get("stdout", ""),
            }
            for field in ("stderr", "stdout_artifact", "stderr_artifact"):
                if result.get(field):
                    failure[field] = result[field]
            return failure
        if mode in ("decompile", "disassemble"):
            key = "decompiled" if mode == "decompile" else "disassembled"
            return {"success": True, "binary": binary, "function": script_target, key: inspected}
        return {**inspected, "success": True, "mode": mode}

    result = run_project(analysis_binary, headless, inspect, check_task_cancelled, update_task_progress)
    if result.get("success"):
        payload = result.get("decompiled", result.get("disassembled", result))
        failures = [item for item in payload.get("functions", []) if item.get("error")]
        if payload.get("error") or failures:
            # A failed query does not invalidate a successfully saved analysis.
            result = {**result, "success": False,
                      "error": payload.get("error") or f"{len(failures)} function(s) failed",
                      "partial": bool(failures) and len(failures) < len(payload["functions"])}
    logger.info("Ghidra mode=%s success=%s error=%s", mode, result.get("success"), result.get("error", ""))
    return result


def run_ghidra_inspection(params: Dict[str, Any], mode: str, extra_args: list[str]) -> Dict[str, Any]:
    """Run the shared Ghidra inspection script and parse its JSON output."""
    return run_ghidra(params, mode, "InspectBinary.java", mode, extra_args)


@app.post("/api/tools/ghidra/decompile")
def ghidra_decompile(params: GhidraRequest):
    """Decompile using a persistent analyzed Ghidra project."""
    params = params.model_dump()
    return run_ghidra(params, "decompile", "DecompileFunction.java", params["function"])


@app.post("/api/tools/ghidra/disassemble")
def ghidra_disassemble(params: GhidraRequest):
    """Disassemble using a persistent analyzed Ghidra project."""
    params = params.model_dump()
    return run_ghidra(params, "disassemble", "DisassembleFunction.java", params["function"])


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


@app.post("/api/tools/disassemble")
def disassemble_binary(params: DisassembleRequest):
    """Prefer Ghidra; auto falls back only when Ghidra is unavailable."""
    import shlex

    if params.async_mode:
        return submit_task(lambda: disassemble_binary(params.model_copy(update={"async_mode": False})),
                           label="disassemble")
    use_ghidra = params.backend == "ghidra" or (params.backend == "auto" and find_ghidra_headless())
    if use_ghidra:
        result = ghidra_disassemble(GhidraRequest(**params.model_dump(exclude={"backend"})))
        return {**result, "backend": "ghidra"}
    if not Path(params.binary).is_file():
        raise ValueError(f"Binary not found: {params.binary}")
    result = execute_command(shlex.join(["objdump", "-M", "intel", "-d", "--", params.binary]),
                             timeout=params.timeout, cache_params=params.model_dump())
    return {**result, "backend": "objdump"}


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
    """Use native PE flags, and reserve checksec(1) for ELF."""
    from bear.analysis import detect_format, pe_metadata, skipped
    import shlex

    params = params.model_dump()
    format_name = detect_format(params["binary"])
    if format_name == "PE":
        return pe_metadata(params["binary"])
    if format_name != "ELF":
        return {**skipped(f"No native security analyzer for {format_name}"), "format": format_name}
    command = f"checksec --file={shlex.quote(params['binary'])}"
    return execute_command(command, use_cache=True, cache_params=params)


@app.post("/api/tools/strings")
def strings(params: StringsRequest):
    """Extract bounded native strings; full-file scanning requires opt-in."""
    from bear.analysis import scan_strings

    options = params.model_dump()
    if options.pop("async_mode"):
        return submit_task(lambda: strings(params.model_copy(update={"async_mode": False})), "strings")
    return scan_strings(options.pop("file_path"), check_cancelled=check_task_cancelled, **options)


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
    from bear.analysis import detect_format, skipped
    import shlex

    params = params.model_dump()
    format_name = detect_format(params["binary"])
    if format_name != "ELF":
        return {**skipped(f"readelf is ELF-only; detected {format_name}"), "format": format_name}
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
    command += f" -- {shlex.quote(params['binary'])}"
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
def list_tasks(offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
    """Page task summaries without duplicating their results."""
    with task_lock:
        tasks = []
        entries = list(task_results.items())
        for task_id, info in entries[offset:offset + limit]:
            entry = {
                "task_id": task_id,
                "status": info["status"],
                "submitted_at": info["submitted_at"],
                "started_at": info["started_at"],
                "completed_at": info["completed_at"],
                "command": info["command"],
                "progress_percent": info.get("progress_percent"),
                "stage": info.get("stage", info["status"]),
                "cancel_requested": info.get("cancel_requested", False),
            }
            if info["status"] == "running" and info["started_at"]:
                entry["runtime_seconds"] = round(time.time() - info["started_at"], 1)
            tasks.append(entry)
    end = min(len(entries), offset + limit)
    return {"success": True, "total": len(entries), "tasks": tasks,
            "offset": offset, "next_offset": end if end < len(entries) else None}


@app.get("/api/tasks/{task_id}")
def get_task(task_id):
    """Get the status and result of a specific async task"""
    with task_lock:
        info = task_results.get(task_id)
        if info is not None:
            info = {key: value for key, value in info.items() if not key.startswith("_")}
    if info is None:
        return JSONResponse(status_code=404, content={"error": f"Task not found: {task_id}"})
    response = {key: value for key, value in info.items() if key not in ("result", "command")}
    if info["status"] == "running" and info["started_at"]:
        response["runtime_seconds"] = round(time.time() - info["started_at"], 1)
    if info["status"] in ("completed", "failed") and info["result"] is not None:
        response["result"] = info["result"]
    return response


@app.delete("/api/tasks/{task_id}")
def cancel_task(task_id):
    """Request cancellation; report cancelled only once the worker has cleaned up."""
    with task_lock:
        info = task_results.get(task_id)
        if info is None:
            raise HTTPException(404, f"Task not found: {task_id}")
        status = info["status"]
        if status in ("completed", "failed", "cancelled"):
            return JSONResponse(status_code=400, content={
                "success": False, "task_id": task_id, "error": f"Task already {status}, cannot cancel"})
        info["cancel_requested"] = True
        info["_cancel_event"].set()
    return {"success": True, "task_id": task_id, "status": status, "cancel_requested": True}


@app.get("/api/artifacts/{artifact_id}", response_class=JSONResponse)
def get_artifact(artifact_id: str, offset: int = Query(0, ge=0), limit: int = Query(8192, ge=1, le=8192)):
    """Read a byte page, encoded losslessly as base64."""
    try:
        return read_artifact(artifact_id, offset, limit)
    except FileNotFoundError:
        raise HTTPException(404, "Artifact not found") from None


# ============================================================================
# MAIN
# ============================================================================

BANNER = ModernVisualEngine.create_banner(VERSION)

def main():
    """Run the BEAR API server."""
    print(BANNER)

    parser = argparse.ArgumentParser(description="BEAR - Binary Exploitation & Automated Reversing Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--host", default=API_HOST, help=f"Bind address (default: {API_HOST})")
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

    uvicorn.run("bear.server:app", host=args.host, port=port, reload=debug_mode, log_level="debug" if debug_mode else "info")


if __name__ == "__main__":
    main()
