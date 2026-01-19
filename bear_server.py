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
- Volatility, Volatility3 - Memory forensics framework
- MSFVenom - Payload generator
- UPX - Executable packer/unpacker

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
import psutil

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('bear.log')
        ]
    )
except PermissionError:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# API Configuration
API_PORT = int(os.environ.get('BEAR_PORT', 8888))
API_HOST = os.environ.get('BEAR_HOST', '127.0.0.1')
DEBUG_MODE = False
VERSION = "1.1.1"

# Command execution settings
COMMAND_TIMEOUT = int(os.environ.get('BEAR_TIMEOUT', 300))
CACHE_SIZE = int(os.environ.get('BEAR_CACHE_SIZE', 1000))
CACHE_TTL = int(os.environ.get('BEAR_CACHE_TTL', 3600))

# Global process management
active_processes: Dict[int, Dict[str, Any]] = {}
process_lock = threading.Lock()


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
        logger.info(f"Executing: {self.command}")

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
    binary_tools = [
        "gdb", "radare2", "binwalk", "ropgadget", "checksec", "objdump",
        "one-gadget", "ropper", "angr", "pwninit", "strings",
        "xxd", "readelf", "hexdump", "upx", "volatility", "msfvenom"
    ]

    tools_status = {}
    for tool in binary_tools:
        try:
            result = execute_command(f"which {tool}", use_cache=True)
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    # Check Ghidra separately using find_ghidra_headless
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
def gdb():
    """Execute GDB for binary analysis and debugging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        script_file = params.get("script_file", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"gdb {binary}"
        if script_file:
            command += f" -x {script_file}"
        if commands:
            temp_script = "/tmp/gdb_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command += f" -x {temp_script}"
        if additional_args:
            command += f" {additional_args}"
        command += " -batch"

        result = execute_command(command)

        if commands and os.path.exists("/tmp/gdb_commands.txt"):
            try:
                os.remove("/tmp/gdb_commands.txt")
            except:
                pass

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/gdb-peda", methods=["POST"])
def gdb_peda():
    """Execute GDB with PEDA for enhanced debugging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        attach_pid = params.get("attach_pid", 0)
        core_file = params.get("core_file", "")
        additional_args = params.get("additional_args", "")

        if not binary and not attach_pid and not core_file:
            return jsonify({"error": "Binary, PID, or core file is required"}), 400

        command = "gdb -q"
        if binary:
            command += f" {binary}"
        if core_file:
            command += f" {core_file}"
        if attach_pid:
            command += f" -p {attach_pid}"

        if commands:
            temp_script = "/tmp/gdb_peda_commands.txt"
            peda_commands = f"source ~/peda/peda.py\n{commands}\nquit"
            with open(temp_script, "w") as f:
                f.write(peda_commands)
            command += f" -x {temp_script}"
        else:
            command += " -ex 'source ~/peda/peda.py' -ex 'quit'"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)

        if commands and os.path.exists("/tmp/gdb_peda_commands.txt"):
            try:
                os.remove("/tmp/gdb_peda_commands.txt")
            except:
                pass

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/gdb-gef", methods=["POST"])
def gdb_gef():
    """Execute GDB with GEF for exploit development"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        attach_pid = params.get("attach_pid", 0)
        core_file = params.get("core_file", "")
        additional_args = params.get("additional_args", "")

        if not binary and not attach_pid and not core_file:
            return jsonify({"error": "Binary, PID, or core file is required"}), 400

        command = "gdb -q"
        if binary:
            command += f" {binary}"
        if core_file:
            command += f" {core_file}"
        if attach_pid:
            command += f" -p {attach_pid}"

        if commands:
            temp_script = "/tmp/gdb_gef_commands.txt"
            gef_commands = f"source ~/.gdbinit-gef.py\n{commands}\nquit"
            with open(temp_script, "w") as f:
                f.write(gef_commands)
            command += f" -x {temp_script}"
        else:
            command += " -ex 'source ~/.gdbinit-gef.py' -ex 'quit'"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)

        if commands and os.path.exists("/tmp/gdb_gef_commands.txt"):
            try:
                os.remove("/tmp/gdb_gef_commands.txt")
            except:
                pass

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/radare2", methods=["POST"])
def radare2():
    """Execute Radare2 for binary analysis"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        if commands:
            temp_script = "/tmp/r2_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command = f"r2 -i {temp_script} -q {binary}"
        else:
            command = f"r2 -q {binary}"

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)

        if commands and os.path.exists("/tmp/r2_commands.txt"):
            try:
                os.remove("/tmp/r2_commands.txt")
            except:
                pass

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/ghidra/decompile", methods=["POST"])
def ghidra_decompile():
    """Decompile binary using Ghidra headless mode with custom script"""
    try:
        params = request.json
        if not params:
            return jsonify({"error": "Request body must be JSON with Content-Type: application/json"}), 400

        binary = params.get("binary", "")
        function_name = params.get("function", "all")
        analysis_timeout = params.get("timeout", 300)

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        if not os.path.exists(binary):
            return jsonify({"error": f"Binary not found: {binary}"}), 400

        # Find Ghidra analyzeHeadless
        ghidra_headless = find_ghidra_headless()
        if not ghidra_headless:
            return jsonify({"error": "Ghidra analyzeHeadless not found. Set GHIDRA_HEADLESS environment variable."}), 500

        # Get the script path relative to this file
        script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")
        decompile_script = "DecompileFunction.java"

        if not os.path.exists(os.path.join(script_dir, decompile_script)):
            return jsonify({"error": f"Decompile script not found: {script_dir}/{decompile_script}"}), 500

        project_dir = f"/tmp/ghidra_projects/decompile_{os.path.basename(binary)}_{int(time.time())}"
        os.makedirs(project_dir, exist_ok=True)

        # Build the command
        command = f'"{ghidra_headless}" "{project_dir}" decompile_project -import "{binary}" -scriptPath "{script_dir}" -postScript {decompile_script} "{function_name}" -deleteProject'

        result = execute_command(command, timeout=analysis_timeout)

        # Parse the JSON output from the script
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
                    return jsonify({
                        "success": True,
                        "binary": binary,
                        "function": function_name,
                        "decompiled": decompiled
                    })
                except json.JSONDecodeError as e:
                    return jsonify({
                        "success": False,
                        "error": f"Failed to parse decompilation output: {str(e)}",
                        "raw_output": stdout
                    })

        return jsonify({
            "success": False,
            "error": "Decompilation failed or produced no output",
            "details": result
        })

    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/binwalk", methods=["POST"])
def binwalk():
    """Execute Binwalk for firmware analysis"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        extract = params.get("extract", False)
        additional_args = params.get("additional_args", "")

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        command = "binwalk"
        if extract:
            command += " -e"
        if additional_args:
            command += f" {additional_args}"
        command += f" {file_path}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# BINARY ANALYSIS TOOLS - INSPECTION
# ============================================================================

@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """Check security features of a binary"""
    try:
        params = request.json
        binary = params.get("binary", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"checksec --file={binary}"
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/strings", methods=["POST"])
def strings():
    """Extract strings from a binary"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        min_len = params.get("min_len", 4)
        encoding = params.get("encoding", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        command = f"strings -n {min_len}"
        if encoding:
            command += f" -e {encoding}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {file_path}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/objdump", methods=["POST"])
def objdump():
    """Analyze a binary using objdump"""
    try:
        params = request.json
        binary = params.get("binary", "")
        disassemble = params.get("disassemble", True)
        section = params.get("section", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = "objdump -M intel"
        if disassemble:
            command += " -d"
        else:
            command += " -x"
        if section:
            command += f" -j {section}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {binary}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/readelf", methods=["POST"])
def readelf():
    """Analyze ELF file headers and structure"""
    try:
        params = request.json
        binary = params.get("binary", "")
        headers = params.get("headers", True)
        symbols = params.get("symbols", False)
        sections = params.get("sections", False)
        all_info = params.get("all_info", False)
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = "readelf"
        if all_info:
            command += " -a"
        else:
            if headers:
                command += " -h"
            if symbols:
                command += " -s"
            if sections:
                command += " -S"
        if additional_args:
            command += f" {additional_args}"
        command += f" {binary}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/xxd", methods=["POST"])
def xxd():
    """Create a hex dump using xxd"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        offset = params.get("offset", "0")
        length = params.get("length", "")
        cols = params.get("cols", 16)
        additional_args = params.get("additional_args", "")

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        command = f"xxd -s {offset}"
        if length:
            command += f" -l {length}"
        command += f" -c {cols}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {file_path}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/hexdump", methods=["POST"])
def hexdump():
    """Create a hex dump using hexdump"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        format_type = params.get("format_type", "canonical")
        offset = params.get("offset", "0")
        length = params.get("length", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        command = "hexdump"
        if format_type == "canonical":
            command += " -C"
        elif format_type == "one-byte-octal":
            command += " -b"
        elif format_type == "two-byte-decimal":
            command += " -d"
        if offset != "0":
            command += f" -s {offset}"
        if length:
            command += f" -n {length}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {file_path}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# BINARY ANALYSIS TOOLS - EXPLOIT DEVELOPMENT
# ============================================================================

@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """Search for ROP gadgets using ROPgadget"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "")
        rop_chain = params.get("rop_chain", False)
        depth = params.get("depth", 10)
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"ROPgadget --binary {binary}"
        if gadget_type:
            command += f" --only '{gadget_type}'"
        if rop_chain:
            command += " --ropchain"
        command += f" --depth {depth}"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/ropper", methods=["POST"])
def ropper():
    """Execute ropper for ROP/JOP gadget searching"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "rop")
        quality = params.get("quality", 1)
        arch = params.get("arch", "")
        search_string = params.get("search_string", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"ropper --file {binary}"
        if gadget_type == "rop":
            command += " --rop"
        elif gadget_type == "jop":
            command += " --jop"
        elif gadget_type == "sys":
            command += " --sys"
        elif gadget_type == "all":
            command += " --all"
        if quality > 1:
            command += f" --quality {quality}"
        if arch:
            command += f" --arch {arch}"
        if search_string:
            command += f" --search '{search_string}'"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/one-gadget", methods=["POST"])
def one_gadget():
    """Find one-shot RCE gadgets in libc"""
    try:
        params = request.json
        libc_path = params.get("libc_path", "")
        level = params.get("level", 1)
        additional_args = params.get("additional_args", "")

        if not libc_path:
            return jsonify({"error": "libc_path parameter is required"}), 400

        command = f"one_gadget {libc_path} --level {level}"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/pwntools", methods=["POST"])
def pwntools():
    """Execute Pwntools for exploit development"""
    try:
        params = request.json
        script_content = params.get("script_content", "")
        target_binary = params.get("target_binary", "")
        target_host = params.get("target_host", "")
        target_port = params.get("target_port", 0)
        exploit_type = params.get("exploit_type", "local")
        additional_args = params.get("additional_args", "")

        if not script_content and not target_binary:
            return jsonify({"error": "Script content or target binary is required"}), 400

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
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)

        try:
            os.remove(script_file)
        except:
            pass

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/angr", methods=["POST"])
def angr():
    """Execute angr for symbolic execution"""
    try:
        params = request.json
        binary = params.get("binary", "")
        script_content = params.get("script_content", "")
        find_address = params.get("find_address", "")
        avoid_addresses = params.get("avoid_addresses", "")
        analysis_type = params.get("analysis_type", "symbolic")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

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
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command, timeout=600)

        try:
            os.remove(script_file)
        except:
            pass

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/libc-database", methods=["POST"])
def libc_database():
    """Libc identification and offset lookup"""
    try:
        params = request.json
        action = params.get("action", "find")
        symbols = params.get("symbols", "")
        libc_id = params.get("libc_id", "")
        additional_args = params.get("additional_args", "")

        if action == "find" and not symbols:
            return jsonify({"error": "Symbols parameter is required for find action"}), 400
        if action in ["dump", "download"] and not libc_id:
            return jsonify({"error": "libc_id parameter is required for dump/download actions"}), 400

        base_command = "cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null"

        if action == "find":
            command = f"{base_command} && ./find {symbols}"
        elif action == "dump":
            command = f"{base_command} && ./dump {libc_id}"
        elif action == "download":
            command = f"{base_command} && ./download {libc_id}"
        else:
            return jsonify({"error": f"Invalid action: {action}"}), 400

        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/pwninit", methods=["POST"])
def pwninit():
    """CTF binary exploitation setup"""
    try:
        params = request.json
        binary = params.get("binary", "")
        libc = params.get("libc", "")
        ld = params.get("ld", "")
        template_type = params.get("template_type", "python")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"pwninit --bin {binary}"
        if libc:
            command += f" --libc {libc}"
        if ld:
            command += f" --ld {ld}"
        if template_type:
            command += f" --template-type {template_type}"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# BINARY ANALYSIS TOOLS - PACKING/UNPACKING
# ============================================================================

@app.route("/api/tools/upx", methods=["POST"])
def upx():
    """Execute UPX for packing/unpacking"""
    try:
        params = request.json
        binary = params.get("binary", "")
        action = params.get("action", "decompress")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            return jsonify({"error": "Binary parameter is required"}), 400

        command = "upx"
        if action == "decompress":
            command += " -d"
        elif action == "compress":
            command += " -9"
        elif action == "test":
            command += " -t"
        elif action == "list":
            command += " -l"

        if output_file:
            command += f" -o {output_file}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {binary}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# MEMORY FORENSICS
# ============================================================================

@app.route("/api/tools/volatility", methods=["POST"])
def volatility():
    """Execute Volatility for memory forensics"""
    try:
        params = request.json
        memory_file = params.get("memory_file", "")
        plugin = params.get("plugin", "")
        profile = params.get("profile", "")
        additional_args = params.get("additional_args", "")

        if not memory_file:
            return jsonify({"error": "Memory file parameter is required"}), 400
        if not plugin:
            return jsonify({"error": "Plugin parameter is required"}), 400

        command = f"volatility -f {memory_file}"
        if profile:
            command += f" --profile={profile}"
        command += f" {plugin}"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/volatility3", methods=["POST"])
def volatility3():
    """Execute Volatility3 for advanced memory forensics"""
    try:
        params = request.json
        memory_file = params.get("memory_file", "")
        plugin = params.get("plugin", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not memory_file:
            return jsonify({"error": "Memory file parameter is required"}), 400
        if not plugin:
            return jsonify({"error": "Plugin parameter is required"}), 400

        command = f"vol -f {memory_file} {plugin}"
        if output_file:
            command += f" > {output_file}"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ============================================================================
# PAYLOAD GENERATION
# ============================================================================

@app.route("/api/tools/msfvenom", methods=["POST"])
def msfvenom():
    """Execute MSFVenom for payload generation"""
    try:
        params = request.json
        payload = params.get("payload", "")
        format_type = params.get("format", "")
        output_file = params.get("output_file", "")
        encoder = params.get("encoder", "")
        iterations = params.get("iterations", "")
        lhost = params.get("lhost", "")
        lport = params.get("lport", "")
        additional_args = params.get("additional_args", "")

        if not payload:
            return jsonify({"error": "Payload parameter is required"}), 400

        command = f"msfvenom -p {payload}"
        if lhost:
            command += f" LHOST={lhost}"
        if lport:
            command += f" LPORT={lport}"
        if format_type:
            command += f" -f {format_type}"
        if output_file:
            command += f" -o {output_file}"
        if encoder:
            command += f" -e {encoder}"
        if iterations:
            command += f" -i {iterations}"
        if additional_args:
            command += f" {additional_args}"

        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
