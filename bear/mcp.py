#!/usr/bin/env python3
"""
BEAR MCP Client - Binary Exploitation & Automated Reversing Interface

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

Architecture: MCP Client for AI agent communication with BEAR server
Framework: FastMCP integration for tool orchestration
"""

import sys
import argparse
import logging
from typing import Dict, Any, Literal, Optional
from urllib.parse import quote
import requests
import time
from urllib3.exceptions import ConnectTimeoutError, MaxRetryError

from fastmcp import FastMCP

from bear.ui import ColoredFormatter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[BEAR MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr)
    ]
)

for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[BEAR MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

# Default configuration
VERSION = "1.4.0"
DEFAULT_BEAR_SERVER = "http://127.0.0.1:8888"
DEFAULT_REQUEST_TIMEOUT = 300
MAX_RETRIES = 3
CONNECT_TIMEOUT = 3
RETRY_BACKOFF = 0.1

class BearClient:
    """Lazy API client: backend outages never prevent MCP tool registration."""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("GET", endpoint, params=params or {})

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("POST", endpoint, json=json_data)

    def safe_delete(self, endpoint: str) -> Dict[str, Any]:
        return self._request("DELETE", endpoint)

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        for attempt in range(MAX_RETRIES):
            try:
                # Disable redirects too: a 307/308 could replay a mutation POST.
                response = self.session.request(
                    method, url, timeout=(min(CONNECT_TIMEOUT, self.timeout), self.timeout),
                    allow_redirects=False, **kwargs,
                )
                response.raise_for_status()
                if 300 <= response.status_code < 400:
                    raise requests.exceptions.HTTPError("Unexpected backend redirect", response=response)
                result = response.json()
                if not isinstance(result, dict):
                    raise ValueError("Expected a JSON object from the BEAR backend")
                return result
            except (requests.exceptions.RequestException, ValueError) as error:
                # requests wraps urllib3's connection-establishment failures in
                # MaxRetryError. A generic ConnectionError can instead be a read
                # reset after command execution and must NOT replay a mutation.
                cause = error.args[0] if error.args else None
                not_sent = isinstance(error, requests.exceptions.ConnectTimeout) or (
                    isinstance(error, requests.exceptions.ConnectionError)
                    and isinstance(cause, MaxRetryError)
                    and isinstance(cause.reason, ConnectTimeoutError)
                )
                network_error = isinstance(error, (
                    requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                    requests.exceptions.ChunkedEncodingError,
                ))
                status_code = (
                    error.response.status_code
                    if isinstance(error, requests.exceptions.HTTPError) and error.response is not None
                    else None
                )
                unavailable = network_error or status_code in (502, 503, 504)
                retryable = not_sent or (method == "GET" and unavailable)
                if retryable and attempt + 1 < MAX_RETRIES:
                    if getattr(error, "response", None) is not None:
                        error.response.close()
                    time.sleep(RETRY_BACKOFF * 2 ** attempt)
                    continue

                outcome_unknown = method != "GET" and not not_sent
                hint = (
                    "The backend may have executed this operation. It was not replayed after "
                    "this failure; check task/process status before submitting it again."
                    if outcome_unknown else
                    "Check that the BEAR backend is running at server_url, then try again. "
                    "This MCP process can use it once it is available."
                )
                message = f"BEAR backend {'unavailable' if unavailable else 'request failed'}: {error}"
                logger.error("%s %s: %s", method, url, message)
                result = {
                    "success": False,
                    "error": message,
                    "error_code": "backend_unavailable" if unavailable else (
                        "http_error" if status_code is not None else "invalid_response"
                    ),
                    "server_url": self.server_url,
                    "method": method,
                    "endpoint": endpoint,
                    "attempts": attempt + 1,
                    "retryable": retryable,
                    "outcome_unknown": outcome_unknown,
                    "hint": hint,
                }
                if status_code is not None:
                    result["status_code"] = status_code
                return result

    def execute_command(self, command: str, use_cache: bool = True,
                        async_mode: bool = False, timeout: int = 300) -> Dict[str, Any]:
        return self.safe_post("api/command", {
            "command": command, "use_cache": use_cache,
            "async_mode": async_mode, "timeout": timeout,
        })

    def check_health(self, verbose: bool = False) -> Dict[str, Any]:
        params = {"verbose": "true"} if verbose else None
        return self.safe_get("health", params=params)


def setup_mcp_server(bear_client: BearClient) -> FastMCP:
    """Set up the MCP server with Binary Analysis & Reverse Engineering tools"""
    mcp = FastMCP("bear-mcp")

    # ============================================================================
    # CORE BINARY ANALYSIS TOOLS
    # ============================================================================

    @mcp.tool()
    def gdb_analyze(binary: str, commands: str = "", script_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB for binary analysis and debugging.

        Args:
            binary: Path to the binary file
            commands: GDB commands to execute (separated by semicolons)
            script_file: Path to GDB script file
            additional_args: Additional GDB arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "commands": commands,
            "script_file": script_file,
            "additional_args": additional_args
        }
        logger.info(f"Starting GDB analysis: {binary}")
        result = bear_client.safe_post("api/tools/gdb", data)
        if result.get("success"):
            logger.info(f"GDB analysis completed for {binary}")
        else:
            logger.error(f"GDB analysis failed for {binary}")
        return result

    @mcp.tool()
    def gdb_peda_debug(binary: str = "", commands: str = "", attach_pid: int = 0,
                      core_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB with PEDA for enhanced debugging and exploitation.

        Args:
            binary: Binary to debug
            commands: GDB commands to execute
            attach_pid: Process ID to attach to
            core_file: Core dump file to analyze
            additional_args: Additional GDB arguments

        Returns:
            Enhanced debugging results with PEDA
        """
        data = {
            "binary": binary,
            "commands": commands,
            "attach_pid": attach_pid,
            "core_file": core_file,
            "additional_args": additional_args
        }
        logger.info(f"Starting GDB-PEDA analysis: {binary or f'PID {attach_pid}' or core_file}")
        result = bear_client.safe_post("api/tools/gdb-peda", data)
        if result.get("success"):
            logger.info(f"GDB-PEDA analysis completed")
        else:
            logger.error(f"GDB-PEDA analysis failed")
        return result

    @mcp.tool()
    def gdb_gef_debug(binary: str = "", commands: str = "", attach_pid: int = 0,
                     core_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute GDB with GEF (GDB Enhanced Features) for exploit development.

        Args:
            binary: Binary to debug
            commands: GDB commands to execute
            attach_pid: Process ID to attach to
            core_file: Core dump file to analyze
            additional_args: Additional GDB arguments

        Returns:
            Enhanced debugging results with GEF
        """
        data = {
            "binary": binary,
            "commands": commands,
            "attach_pid": attach_pid,
            "core_file": core_file,
            "additional_args": additional_args
        }
        logger.info(f"Starting GDB-GEF analysis: {binary or f'PID {attach_pid}' or core_file}")
        result = bear_client.safe_post("api/tools/gdb-gef", data)
        if result.get("success"):
            logger.info(f"GDB-GEF analysis completed")
        else:
            logger.error(f"GDB-GEF analysis failed")
        return result

    @mcp.tool()
    def radare2_analyze(binary: str, commands: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Radare2 for binary analysis and reverse engineering.

        Args:
            binary: Path to the binary file
            commands: Radare2 commands to execute
            additional_args: Additional Radare2 arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "commands": commands,
            "additional_args": additional_args
        }
        logger.info(f"Starting Radare2 analysis: {binary}")
        result = bear_client.safe_post("api/tools/radare2", data)
        if result.get("success"):
            logger.info(f"Radare2 analysis completed for {binary}")
        else:
            logger.error(f"Radare2 analysis failed for {binary}")
        return result

    @mcp.tool()
    def triage_binary(binary: str, strings_limit: int = 40, use_cache: bool = True,
                      full_scan: bool = False, compute_hash: bool = False,
                      offset: int = 0, length: Optional[int] = None,
                      max_scan_bytes: int = 16777216, include_resources: bool = False,
                      async_mode: bool = False) -> Dict[str, Any]:
        """
        Run bounded, format-aware binary triage with optional whole-file SHA256.

        Args:
            binary: Path to the binary file
            strings_limit: Maximum number of strings to include
            use_cache: Whether to use server-side command cache
            full_scan: Allow full-file analysis; an explicit strings window still applies
            compute_hash: Explicitly compute a streamed whole-file SHA256
            async_mode: Return a task_id immediately, recommended for whole-file work
            offset: Absolute file-byte offset for the strings window
            length: Optional byte length of the strings window
            max_scan_bytes: Maximum bytes to scan by default (16 MiB)
            include_resources: Include PE resources in the strings scan

        Returns:
            Triage summary and command outputs
        """
        data = {
            "binary": binary,
            "strings_limit": strings_limit,
            "use_cache": use_cache,
            "full_scan": full_scan,
            "compute_hash": compute_hash,
            "async_mode": async_mode,
            "offset": offset,
            "length": length,
            "max_scan_bytes": max_scan_bytes,
            "include_resources": include_resources,
        }
        logger.info(f"Starting binary triage: {binary}")
        result = bear_client.safe_post("api/tools/triage", data)
        if result.get("success"):
            logger.info(f"Binary triage completed for {binary}")
        else:
            logger.error(f"Binary triage failed for {binary}")
        return result

    @mcp.tool()
    def ghidra_decompile(binary: str, function: str = "all", timeout: int = 300,
                         async_mode: bool = False) -> Dict[str, Any]:
        """
        Decompile a binary using Ghidra and return C-like pseudocode.

        Args:
            binary: Path to the binary file to decompile
            function: Function to decompile - can be:
                      - "all" to decompile all functions
                      - function name (e.g., "main", "vulnerable_func")
                      - address (e.g., "0x401000")
            timeout: Analysis timeout in seconds (default 300)
            async_mode: If True, submit as background task and return task_id immediately.
                        Use get_task_status(task_id) to poll for results.

        Returns:
            Decompiled C-like pseudocode, or task submission info if async_mode=True
        """
        data = {
            "binary": binary,
            "function": function,
            "timeout": timeout,
            "async_mode": async_mode
        }
        logger.info(f"Starting Ghidra decompilation: {binary} function={function} async={async_mode}")
        result = bear_client.safe_post("api/tools/ghidra/decompile", data)
        if result.get("success"):
            if async_mode:
                logger.info(f"Ghidra task submitted: {result.get('task_id')}")
            else:
                logger.info(f"Ghidra decompilation completed for {binary}")
        else:
            logger.error(f"Ghidra decompilation failed for {binary}")
        return result

    @mcp.tool()
    def ghidra_disassemble(binary: str, function: str = "all", timeout: int = 300,
                           async_mode: bool = False) -> Dict[str, Any]:
        """
        Disassemble a binary using Ghidra and return structured instructions.

        Args:
            binary: Path to the binary file to disassemble
            function: Function to disassemble, address, or "all"
            timeout: Analysis timeout in seconds (default 300)
            async_mode: If True, submit as background task and return task_id immediately.

        Returns:
            Structured Ghidra disassembly, or task submission info if async_mode=True
        """
        data = {
            "binary": binary,
            "function": function,
            "timeout": timeout,
            "async_mode": async_mode
        }
        logger.info(f"Starting Ghidra disassembly: {binary} function={function} async={async_mode}")
        result = bear_client.safe_post("api/tools/ghidra/disassemble", data)
        if result.get("success"):
            if async_mode:
                logger.info(f"Ghidra disassembly task submitted: {result.get('task_id')}")
            else:
                logger.info(f"Ghidra disassembly completed for {binary}")
        else:
            logger.error(f"Ghidra disassembly failed for {binary}")
        return result

    @mcp.tool()
    def ghidra_functions(binary: str, timeout: int = 300, async_mode: bool = False) -> Dict[str, Any]:
        """
        List functions discovered by Ghidra with addresses, signatures, namespaces, and sizes.

        Args:
            binary: Path to the binary file
            timeout: Analysis timeout in seconds
            async_mode: If True, submit as background task and return task_id immediately.

        Returns:
            Structured function list from Ghidra
        """
        data = {"binary": binary, "timeout": timeout, "async_mode": async_mode}
        logger.info(f"Listing Ghidra functions: {binary} async={async_mode}")
        result = bear_client.safe_post("api/tools/ghidra/functions", data)
        if result.get("success"):
            logger.info(f"Ghidra function listing completed for {binary}")
        else:
            logger.error(f"Ghidra function listing failed for {binary}")
        return result

    @mcp.tool()
    def ghidra_xrefs(binary: str, target: str, direction: str = "both",
                     target_type: str = "auto", timeout: int = 300,
                     async_mode: bool = False) -> Dict[str, Any]:
        """
        Find Ghidra cross-references to/from a function, symbol, string, or address.

        Args:
            binary: Path to the binary file
            target: Function name, symbol, string, or address to inspect
            direction: to, from, or both
            target_type: auto, function, address, string, or symbol
            timeout: Analysis timeout in seconds
            async_mode: If True, submit as background task and return task_id immediately.

        Returns:
            Structured xrefs_to and xrefs_from results
        """
        data = {
            "binary": binary,
            "target": target,
            "direction": direction,
            "target_type": target_type,
            "timeout": timeout,
            "async_mode": async_mode,
        }
        logger.info(f"Finding Ghidra xrefs: {binary} target={target} direction={direction}")
        result = bear_client.safe_post("api/tools/ghidra/xrefs", data)
        if result.get("success"):
            logger.info(f"Ghidra xrefs completed for {target}")
        else:
            logger.error(f"Ghidra xrefs failed for {target}")
        return result

    @mcp.tool()
    def ghidra_callgraph(binary: str, function: str = "all", direction: str = "out",
                         depth: int = 2, timeout: int = 300,
                         async_mode: bool = False) -> Dict[str, Any]:
        """
        Build a Ghidra call graph for all functions or a selected root function/address.

        Args:
            binary: Path to the binary file
            function: Function name/address root, or all
            direction: out, in, or both
            depth: Recursion depth, 1-10
            timeout: Analysis timeout in seconds
            async_mode: If True, submit as background task and return task_id immediately.

        Returns:
            Structured call graph adjacency map
        """
        data = {
            "binary": binary,
            "function": function,
            "direction": direction,
            "depth": depth,
            "timeout": timeout,
            "async_mode": async_mode,
        }
        logger.info(f"Building Ghidra callgraph: {binary} function={function} depth={depth}")
        result = bear_client.safe_post("api/tools/ghidra/callgraph", data)
        if result.get("success"):
            logger.info(f"Ghidra callgraph completed for {binary}")
        else:
            logger.error(f"Ghidra callgraph failed for {binary}")
        return result

    @mcp.tool()
    def binwalk_analyze(file_path: str, extract: bool = False, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Binwalk for firmware and file analysis.

        Args:
            file_path: Path to the file to analyze
            extract: Whether to extract discovered files
            additional_args: Additional Binwalk arguments

        Returns:
            Firmware analysis results
        """
        data = {
            "file_path": file_path,
            "extract": extract,
            "additional_args": additional_args
        }
        logger.info(f"Starting Binwalk analysis: {file_path}")
        result = bear_client.safe_post("api/tools/binwalk", data)
        if result.get("success"):
            logger.info(f"Binwalk analysis completed for {file_path}")
        else:
            logger.error(f"Binwalk analysis failed for {file_path}")
        return result

    # ============================================================================
    # BINARY INSPECTION TOOLS
    # ============================================================================

    @mcp.tool()
    def checksec_analyze(binary: str) -> Dict[str, Any]:
        """
        Check security features of a binary (RELRO, Stack Canary, NX, PIE, etc.).

        Args:
            binary: Path to the binary file

        Returns:
            Security features analysis results
        """
        data = {"binary": binary}
        logger.info(f"Starting Checksec analysis: {binary}")
        result = bear_client.safe_post("api/tools/checksec", data)
        if result.get("success"):
            logger.info(f"Checksec analysis completed for {binary}")
        else:
            logger.error(f"Checksec analysis failed for {binary}")
        return result

    @mcp.tool()
    def strings_extract(file_path: str, min_len: int = 4, encoding: str = "", additional_args: str = "",
                        offset: int = 0, max_scan_bytes: int = 16777216, full_scan: bool = False,
                        length: Optional[int] = None, max_strings: int = 1000,
                        include_resources: bool = False, async_mode: bool = False) -> Dict[str, Any]:
        """
        Extract bounded printable strings, skipping PE resources by default.

        Args:
            file_path: Path to the file
            min_len: Minimum string length (default: 4)
            encoding: String encoding (s=single-byte, S=single-byte+unicode, b=big-endian, l=little-endian)
            additional_args: Must be empty; use explicit bounded scan options instead
            offset: Byte offset at which to start scanning
            max_scan_bytes: Maximum bytes to scan by default (16 MiB)
            full_scan: Remove default size/resource exclusions; an explicit length still applies
            length: Optional byte length of the absolute file window
            max_strings: Maximum number of strings to return (1-10000)
            include_resources: Include PE resource sections in the scan
            async_mode: Return a task_id immediately, recommended for full_scan

        Returns:
            String extraction results
        """
        data = {
            "file_path": file_path,
            "min_len": min_len,
            "encoding": encoding,
            "additional_args": additional_args,
            "offset": offset,
            "max_scan_bytes": max_scan_bytes,
            "full_scan": full_scan,
            "length": length,
            "max_strings": max_strings,
            "include_resources": include_resources,
            "async_mode": async_mode,
        }
        logger.info(f"Starting Strings extraction: {file_path}")
        result = bear_client.safe_post("api/tools/strings", data)
        if result.get("success"):
            logger.info(f"Strings extraction completed for {file_path}")
        else:
            logger.error(f"Strings extraction failed for {file_path}")
        return result

    @mcp.tool()
    def objdump_analyze(binary: str, disassemble: bool = True, section: str = "",
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Analyze a binary using objdump with Intel syntax.

        Prefer disassemble_binary for normal disassembly (Ghidra by default).
        Use this tool for explicit objdump options or file metadata.

        Args:
            binary: Path to the binary file
            disassemble: Whether to disassemble the binary
            section: Specific section to analyze (e.g., .text, .data)
            additional_args: Additional objdump arguments

        Returns:
            Binary analysis results
        """
        data = {
            "binary": binary,
            "disassemble": disassemble,
            "section": section,
            "additional_args": additional_args
        }
        logger.info(f"Starting Objdump analysis: {binary}")
        result = bear_client.safe_post("api/tools/objdump", data)
        if result.get("success"):
            logger.info(f"Objdump analysis completed for {binary}")
        else:
            logger.error(f"Objdump analysis failed for {binary}")
        return result

    @mcp.tool()
    def disassemble_binary(binary: str, function: str = "all", backend: str = "auto",
                           timeout: int = 300, async_mode: bool = False) -> Dict[str, Any]:
        """
        Disassemble a binary, preferring Ghidra. Use objdump only when explicitly
        requested or when Ghidra is unavailable, not after an analysis failure.

        Args:
            binary: Path to the binary file
            function: Function name/address for Ghidra; ignored by objdump fallback
            backend: auto, ghidra, or objdump
            timeout: Ghidra analysis timeout in seconds
            async_mode: Submit as a background task and return task_id immediately

        Returns:
            Disassembly result with the backend used
        """
        selected = backend.lower().strip()
        if selected not in ("auto", "ghidra", "objdump"):
            return {"success": False, "error": "backend must be auto, ghidra, or objdump"}

        return bear_client.safe_post("api/tools/disassemble", {
            "binary": binary, "function": function, "backend": selected,
            "timeout": timeout, "async_mode": async_mode,
        })

    @mcp.tool()
    def readelf_analyze(binary: str, headers: bool = True, symbols: bool = False,
                       sections: bool = False, all_info: bool = False,
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Analyze ELF file headers and structure using readelf.

        Args:
            binary: Path to the ELF binary file
            headers: Show ELF header information
            symbols: Show symbol table
            sections: Show section headers
            all_info: Show all information (-a flag)
            additional_args: Additional readelf arguments

        Returns:
            ELF analysis results
        """
        data = {
            "binary": binary,
            "headers": headers,
            "symbols": symbols,
            "sections": sections,
            "all_info": all_info,
            "additional_args": additional_args
        }
        logger.info(f"Starting Readelf analysis: {binary}")
        result = bear_client.safe_post("api/tools/readelf", data)
        if result.get("success"):
            logger.info(f"Readelf analysis completed for {binary}")
        else:
            logger.error(f"Readelf analysis failed for {binary}")
        return result

    @mcp.tool()
    def xxd_hexdump(file_path: str, offset: str = "0", length: str = "",
                   cols: int = 16, additional_args: str = "") -> Dict[str, Any]:
        """
        Create a hex dump of a file using xxd.

        Args:
            file_path: Path to the file
            offset: Offset to start reading from (hex or decimal)
            length: Number of bytes to read
            cols: Number of columns (octets per line)
            additional_args: Additional xxd arguments

        Returns:
            Hex dump results
        """
        data = {
            "file_path": file_path,
            "offset": offset,
            "length": length,
            "cols": cols,
            "additional_args": additional_args
        }
        logger.info(f"Starting XXD hex dump: {file_path}")
        result = bear_client.safe_post("api/tools/xxd", data)
        if result.get("success"):
            logger.info(f"XXD hex dump completed for {file_path}")
        else:
            logger.error(f"XXD hex dump failed for {file_path}")
        return result

    @mcp.tool()
    def hexdump_analyze(file_path: str, format_type: str = "canonical",
                       offset: str = "0", length: str = "",
                       additional_args: str = "") -> Dict[str, Any]:
        """
        Create a hex dump using hexdump utility.

        Args:
            file_path: Path to the file
            format_type: Output format (canonical, one-byte-octal, two-byte-decimal, etc.)
            offset: Offset to start reading from
            length: Number of bytes to read
            additional_args: Additional hexdump arguments

        Returns:
            Hex dump results
        """
        data = {
            "file_path": file_path,
            "format_type": format_type,
            "offset": offset,
            "length": length,
            "additional_args": additional_args
        }
        logger.info(f"Starting Hexdump analysis: {file_path}")
        result = bear_client.safe_post("api/tools/hexdump", data)
        if result.get("success"):
            logger.info(f"Hexdump analysis completed for {file_path}")
        else:
            logger.error(f"Hexdump analysis failed for {file_path}")
        return result

    # ============================================================================
    # EXPLOIT DEVELOPMENT TOOLS
    # ============================================================================

    @mcp.tool()
    def ropgadget_search(binary: str, gadget_type: str = "", rop_chain: bool = False,
                        depth: int = 10, additional_args: str = "") -> Dict[str, Any]:
        """
        Search for ROP gadgets in a binary using ROPgadget.

        Args:
            binary: Path to the binary file
            gadget_type: Type of gadgets to search for (jmp, call, etc.)
            rop_chain: Generate a ROP chain automatically
            depth: Maximum gadget depth
            additional_args: Additional ROPgadget arguments

        Returns:
            ROP gadget search results
        """
        data = {
            "binary": binary,
            "gadget_type": gadget_type,
            "rop_chain": rop_chain,
            "depth": depth,
            "additional_args": additional_args
        }
        logger.info(f"Starting ROPgadget search: {binary}")
        result = bear_client.safe_post("api/tools/ropgadget", data)
        if result.get("success"):
            logger.info(f"ROPgadget search completed for {binary}")
        else:
            logger.error(f"ROPgadget search failed for {binary}")
        return result

    @mcp.tool()
    def ropper_gadget_search(binary: str, gadget_type: str = "rop", quality: int = 1,
                            arch: str = "", search_string: str = "",
                            additional_args: str = "") -> Dict[str, Any]:
        """
        Execute ropper for advanced ROP/JOP gadget searching.

        Args:
            binary: Binary to search for gadgets
            gadget_type: Type of gadgets (rop, jop, sys, all)
            quality: Gadget quality level (1-5)
            arch: Target architecture (x86, x86_64, arm, etc.)
            search_string: Specific gadget pattern to search for
            additional_args: Additional ropper arguments

        Returns:
            Advanced ROP/JOP gadget search results
        """
        data = {
            "binary": binary,
            "gadget_type": gadget_type,
            "quality": quality,
            "arch": arch,
            "search_string": search_string,
            "additional_args": additional_args
        }
        logger.info(f"Starting Ropper analysis: {binary}")
        result = bear_client.safe_post("api/tools/ropper", data)
        if result.get("success"):
            logger.info(f"Ropper analysis completed")
        else:
            logger.error(f"Ropper analysis failed")
        return result

    @mcp.tool()
    def one_gadget_search(libc_path: str, level: int = 1, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute one_gadget to find one-shot RCE gadgets in libc.

        Args:
            libc_path: Path to libc binary
            level: Constraint level (0=easy, 1=normal, 2=hard)
            additional_args: Additional one_gadget arguments

        Returns:
            One-shot RCE gadget search results with constraints
        """
        data = {
            "libc_path": libc_path,
            "level": level,
            "additional_args": additional_args
        }
        logger.info(f"Starting one_gadget analysis: {libc_path}")
        result = bear_client.safe_post("api/tools/one-gadget", data)
        if result.get("success"):
            logger.info(f"one_gadget analysis completed")
        else:
            logger.error(f"one_gadget analysis failed")
        return result

    @mcp.tool()
    def pwntools_exploit(script_content: str = "", target_binary: str = "",
                        target_host: str = "", target_port: int = 0,
                        exploit_type: str = "local", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Pwntools for exploit development and automation.

        Args:
            script_content: Python script content using pwntools
            target_binary: Local binary to exploit
            target_host: Remote host to connect to
            target_port: Remote port to connect to
            exploit_type: Type of exploit (local, remote, format_string, rop)
            additional_args: Additional arguments

        Returns:
            Exploit execution results
        """
        data = {
            "script_content": script_content,
            "target_binary": target_binary,
            "target_host": target_host,
            "target_port": target_port,
            "exploit_type": exploit_type,
            "additional_args": additional_args
        }
        logger.info(f"Starting Pwntools exploit: {exploit_type}")
        result = bear_client.safe_post("api/tools/pwntools", data)
        if result.get("success"):
            logger.info(f"Pwntools exploit completed")
        else:
            logger.error(f"Pwntools exploit failed")
        return result

    @mcp.tool()
    def libc_database_lookup(action: str = "find", symbols: str = "",
                            libc_id: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute libc-database for libc identification and offset lookup.

        Args:
            action: Action to perform (find, dump, download)
            symbols: Symbols with offsets for find action (format: "symbol1:offset1 symbol2:offset2")
            libc_id: Libc ID for dump/download actions
            additional_args: Additional arguments

        Returns:
            Libc database lookup results
        """
        data = {
            "action": action,
            "symbols": symbols,
            "libc_id": libc_id,
            "additional_args": additional_args
        }
        logger.info(f"Starting libc-database {action}: {symbols or libc_id}")
        result = bear_client.safe_post("api/tools/libc-database", data)
        if result.get("success"):
            logger.info(f"libc-database {action} completed")
        else:
            logger.error(f"libc-database {action} failed")
        return result

    @mcp.tool()
    def pwninit_setup(binary: str, libc: str = "", ld: str = "",
                     template_type: str = "python", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute pwninit for CTF binary exploitation setup.

        Args:
            binary: Binary file to set up
            libc: Libc file to use
            ld: Loader file to use
            template_type: Template type (python, c)
            additional_args: Additional pwninit arguments

        Returns:
            CTF binary exploitation setup results
        """
        data = {
            "binary": binary,
            "libc": libc,
            "ld": ld,
            "template_type": template_type,
            "additional_args": additional_args
        }
        logger.info(f"Starting pwninit setup: {binary}")
        result = bear_client.safe_post("api/tools/pwninit", data)
        if result.get("success"):
            logger.info(f"pwninit setup completed")
        else:
            logger.error(f"pwninit setup failed")
        return result

    @mcp.tool()
    def generate_payload(payload_type: str = "buffer", size: int = 1024,
                        pattern: str = "A", filename: str = "") -> Dict[str, Any]:
        """
        Generate payloads for testing and exploitation (buffer overflow patterns, etc.).

        Args:
            payload_type: Type of payload (buffer, cyclic, random)
            size: Size of the payload in bytes
            pattern: Pattern to use for buffer payloads
            filename: Custom filename (auto-generated if empty)

        Returns:
            Payload generation results with file path
        """
        data = {
            "type": payload_type,
            "size": size,
            "pattern": pattern
        }
        if filename:
            data["filename"] = filename

        logger.info(f"Generating {payload_type} payload: {size} bytes")
        result = bear_client.safe_post("api/payloads/generate", data)
        if result.get("success"):
            logger.info(f"Payload generated successfully")
        else:
            logger.error(f"Failed to generate payload")
        return result

    # ============================================================================
    # FILE OPERATIONS
    # ============================================================================

    @mcp.tool()
    def pe_resources(binary: Optional[str] = None, resource_type: int | str | None = None,
                     resource_id: int | str | None = None, language: int | str | None = None,
                     offset: int = 0, limit: int = 100, artifact_id: Optional[str] = None) -> Dict[str, Any]:
        """
        List a bounded page of native PE resource metadata, without reading payloads.

        Args:
            binary: Binary path; provide exactly one of binary or artifact_id
            resource_type: Optional integer type or exact name; 10 selects RCDATA
            resource_id: Optional integer ID or exact resource name
            language: Optional integer language ID or exact name
            offset: Number of matching resources to skip
            limit: Maximum metadata entries in this page (1-200)
            artifact_id: Stored artifact to inspect instead of a binary path

        Returns:
            Resource metadata and pagination
        """
        return bear_client.safe_post("api/tools/pe/resources", {
            "binary": binary, "artifact_id": artifact_id, "resource_type": resource_type,
            "resource_id": resource_id, "language": language, "offset": offset, "limit": limit,
        })

    @mcp.tool()
    def pe_resources_extract(resource_id: int | str, binary: Optional[str] = None,
                             resource_type: int | str = 10, language: int | str | None = None,
                             max_bytes: int = 67108864, artifact_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Extract one native PE resource to an artifact, never an inline payload.

        Args:
            resource_id: Integer ID or exact resource name to extract
            binary: Binary path; provide exactly one of binary or artifact_id
            resource_type: Integer type or exact name; defaults to RCDATA (10)
            language: Integer language ID or exact name; required if ambiguous
            max_bytes: Resource size limit in bytes (default 64 MiB, maximum 256 MiB)
            artifact_id: Stored artifact to inspect instead of a binary path

        Returns:
            Resource metadata and artifact reference; use read_artifact for pages
        """
        return bear_client.safe_post("api/tools/pe/resources/extract", {
            "binary": binary, "artifact_id": artifact_id, "resource_type": resource_type,
            "resource_id": resource_id, "language": language, "max_bytes": max_bytes,
        })

    @mcp.tool()
    def pe_resources_batch(operation: Literal["sha256", "extract"], binary: Optional[str] = None,
                           resource_type: int | str | None = None, resource_id: int | str | None = None,
                           language: int | str | None = None, offset: int = 0, limit: int = 100,
                           concurrency: int = 2, max_bytes: int = 67108864,
                           max_total_bytes: int = 268435456, result_offset: int = 0,
                           result_limit: int = 100, artifact_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Submit a bounded PE resource hash/extraction batch as an async task.

        Args:
            operation: sha256 or extract
            binary: Binary path; provide exactly one of binary or artifact_id
            resource_type: Optional integer type or exact name; 10 selects RCDATA
            resource_id: Optional integer ID or exact resource name
            language: Optional integer language ID or exact name
            offset: Number of matching resources to skip
            limit: Maximum resources to process (1-500)
            concurrency: Concurrent workers (1-4)
            max_bytes: Per-resource size limit (default 64 MiB, maximum 256 MiB)
            max_total_bytes: Total size limit (default 256 MiB, maximum 1 GiB)
            result_offset: Number of batch result entries to skip
            result_limit: Maximum result entries to retain (1-200)
            artifact_id: Stored artifact to inspect instead of a binary path

        Returns:
            Async task_id; use get_task_status for progress and paged results.
            Use smaller batches to obtain all results without repeating operations.
        """
        return bear_client.safe_post("api/tools/pe/resources/batch", {
            "binary": binary, "artifact_id": artifact_id, "operation": operation,
            "resource_type": resource_type, "resource_id": resource_id, "language": language,
            "offset": offset, "limit": limit, "concurrency": concurrency,
            "max_bytes": max_bytes, "max_total_bytes": max_total_bytes,
            "result_offset": result_offset, "result_limit": result_limit,
        })

    @mcp.tool()
    def read_artifact(artifact_id: str, offset: int = 0, limit: int = 8192) -> Dict[str, Any]:
        """
        Read one bounded base64 page of a stored large tool output.

        When a result has truncated=true, use artifact.artifact_id here. The
        preview is not the full result; request further pages as needed.

        Args:
            artifact_id: Artifact ID returned by the backend, not a file path
            offset: Byte offset in the stored artifact
            limit: Maximum bytes to read in this page (1-8192)

        Returns:
            Base64 page and pagination metadata from the backend
        """
        if not artifact_id or artifact_id in (".", "..") or offset < 0 or not 1 <= limit <= 8192:
            return {"success": False, "error": "Provide an artifact ID, offset >= 0, and limit between 1 and 8192"}
        return bear_client.safe_get(
            f"api/artifacts/{quote(artifact_id, safe='')}", {"offset": offset, "limit": limit},
        )

    @mcp.tool()
    def create_file(filename: str, content: str, binary: bool = False) -> Dict[str, Any]:
        """
        Create a file with specified content.

        Args:
            filename: Name of the file to create
            content: Content to write to the file
            binary: Whether the content is binary data (base64 encoded)

        Returns:
            File creation results
        """
        data = {
            "filename": filename,
            "content": content,
            "binary": binary
        }
        logger.info(f"Creating file: {filename}")
        result = bear_client.safe_post("api/files/create", data)
        if result.get("success"):
            logger.info(f"File created successfully: {filename}")
        else:
            logger.error(f"Failed to create file: {filename}")
        return result

    @mcp.tool()
    def modify_file(filename: str, content: str, append: bool = False) -> Dict[str, Any]:
        """
        Modify an existing file.

        Args:
            filename: Name of the file to modify
            content: Content to write or append
            append: Whether to append to the file (True) or overwrite (False)

        Returns:
            File modification results
        """
        data = {
            "filename": filename,
            "content": content,
            "append": append
        }
        logger.info(f"Modifying file: {filename}")
        result = bear_client.safe_post("api/files/modify", data)
        if result.get("success"):
            logger.info(f"File modified successfully: {filename}")
        else:
            logger.error(f"Failed to modify file: {filename}")
        return result

    @mcp.tool()
    def delete_file(filename: str) -> Dict[str, Any]:
        """
        Delete a file or directory.

        Args:
            filename: Name of the file or directory to delete

        Returns:
            File deletion results
        """
        data = {"filename": filename}
        logger.info(f"Deleting file: {filename}")
        result = bear_client.safe_post("api/files/delete", data)
        if result.get("success"):
            logger.info(f"File deleted successfully: {filename}")
        else:
            logger.error(f"Failed to delete file: {filename}")
        return result

    @mcp.tool()
    def list_files(directory: str = ".") -> Dict[str, Any]:
        """
        List files in a directory.

        Args:
            directory: Directory to list

        Returns:
            Directory listing results
        """
        logger.info(f"Listing files in directory: {directory}")
        result = bear_client.safe_get("api/files/list", {"directory": directory})
        if result.get("success"):
            file_count = len(result.get("files", []))
            logger.info(f"Listed {file_count} files in {directory}")
        else:
            logger.error(f"Failed to list files in {directory}")
        return result

    # ============================================================================
    # PYTHON ENVIRONMENT MANAGEMENT
    # ============================================================================

    @mcp.tool()
    def install_python_package(package: str, env_name: str = "default") -> Dict[str, Any]:
        """
        Install a Python package in a virtual environment.

        Args:
            package: Name of the Python package to install
            env_name: Name of the virtual environment

        Returns:
            Package installation results
        """
        data = {
            "package": package,
            "env_name": env_name
        }
        logger.info(f"Installing Python package: {package} in env {env_name}")
        result = bear_client.safe_post("api/python/install", data)
        if result.get("success"):
            logger.info(f"Package {package} installed successfully")
        else:
            logger.error(f"Failed to install package {package}")
        return result

    @mcp.tool()
    def execute_python_script(script: str, env_name: str = "default", filename: str = "",
                              async_mode: bool = False, timeout: int = 300) -> Dict[str, Any]:
        """
        Execute a Python script in a virtual environment.

        Args:
            script: Python script content to execute
            env_name: Name of the virtual environment
            filename: Custom script filename (auto-generated if empty)
            async_mode: Submit as a background task and return task_id immediately
            timeout: Execution timeout in seconds

        Returns:
            Script execution results
        """
        data = {
            "script": script,
            "env_name": env_name,
            "async_mode": async_mode,
            "timeout": timeout,
        }
        if filename:
            data["filename"] = filename

        logger.info(f"Executing Python script in env {env_name}")
        result = bear_client.safe_post("api/python/execute", data)
        if result.get("success"):
            logger.info(f"Python script executed successfully")
        else:
            logger.error(f"Python script execution failed")
        return result

    # ============================================================================
    # SYSTEM MONITORING & UTILITIES
    # ============================================================================

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the BEAR server.

        Returns:
            Server health information with tool availability
        """
        logger.info(f"Checking BEAR server health")
        result = bear_client.check_health(verbose=True)
        if result.get("status") == "healthy":
            logger.info(f"Server is healthy - {result.get('total_tools_available', 0)} tools available")
        else:
            logger.warning(f"Server health check returned: {result.get('status', 'unknown')}")
        return result

    @mcp.tool()
    def get_cache_stats() -> Dict[str, Any]:
        """
        Get cache statistics from the server.

        Returns:
            Cache performance statistics
        """
        logger.info(f"Getting cache statistics")
        result = bear_client.safe_get("api/cache/stats")
        if "hit_rate" in result:
            logger.info(f"Cache hit rate: {result.get('hit_rate', 'unknown')}")
        return result

    @mcp.tool()
    def clear_cache() -> Dict[str, Any]:
        """
        Clear the server cache.

        Returns:
            Cache clear operation results
        """
        logger.info(f"Clearing server cache")
        result = bear_client.safe_post("api/cache/clear", {})
        if result.get("success"):
            logger.info(f"Cache cleared successfully")
        else:
            logger.error(f"Failed to clear cache")
        return result

    @mcp.tool()
    def get_telemetry() -> Dict[str, Any]:
        """
        Get system telemetry from the server.

        Returns:
            System performance and usage telemetry
        """
        logger.info(f"Getting system telemetry")
        result = bear_client.safe_get("api/telemetry")
        if "commands_executed" in result:
            logger.info(f"Commands executed: {result.get('commands_executed', 0)}")
        return result

    @mcp.tool()
    def execute_command(command: str, use_cache: bool = True,
                        async_mode: bool = False, timeout: int = 300) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the server.

        Args:
            command: The command to execute
            use_cache: Whether to use caching for this command
            async_mode: Submit as a background task and return task_id immediately
            timeout: Execution timeout in seconds

        Returns:
            Command execution results
        """
        try:
            logger.info(f"Executing command: {command}")
            result = bear_client.execute_command(command, use_cache, async_mode, timeout)
            if "error" in result:
                logger.error(f"Command failed: {result['error']}")
                return {
                    **result,
                    "success": False,
                    "error": result["error"],
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", f"Error executing command: {result['error']}")
                }

            if result.get("success"):
                execution_time = result.get("execution_time", 0)
                logger.info(f"Command completed successfully in {execution_time:.2f}s")
            else:
                logger.warning(f"Command completed with errors")

            return result
        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "stdout": "",
                "stderr": f"Error executing command: {str(e)}"
            }

    # ============================================================================
    # PROCESS MANAGEMENT
    # ============================================================================

    @mcp.tool()
    def list_active_processes() -> Dict[str, Any]:
        """
        List all active processes on the server.

        Returns:
            List of active processes with their status
        """
        logger.info("Listing active processes")
        result = bear_client.safe_get("api/processes/list")
        if result.get("success"):
            logger.info(f"Found {result.get('total_count', 0)} active processes")
        else:
            logger.error("Failed to list processes")
        return result

    @mcp.tool()
    def get_process_status(pid: int) -> Dict[str, Any]:
        """
        Get the status of a specific process.

        Args:
            pid: Process ID to check

        Returns:
            Process status information
        """
        logger.info(f"Checking status of process {pid}")
        result = bear_client.safe_get(f"api/processes/status/{pid}")
        if result.get("success"):
            logger.info(f"Process {pid} status retrieved")
        else:
            logger.error(f"Process {pid} not found or error occurred")
        return result

    @mcp.tool()
    def terminate_process(pid: int) -> Dict[str, Any]:
        """
        Terminate a specific running process.

        Args:
            pid: Process ID to terminate

        Returns:
            Success status of the termination operation
        """
        logger.info(f"Terminating process {pid}")
        result = bear_client.safe_post(f"api/processes/terminate/{pid}", {})
        if result.get("success"):
            logger.info(f"Process {pid} terminated successfully")
        else:
            logger.error(f"Failed to terminate process {pid}")
        return result

    @mcp.tool()
    def pause_process(pid: int) -> Dict[str, Any]:
        """
        Pause a specific running process.

        Args:
            pid: Process ID to pause

        Returns:
            Success status of the pause operation
        """
        logger.info(f"Pausing process {pid}")
        result = bear_client.safe_post(f"api/processes/pause/{pid}", {})
        if result.get("success"):
            logger.info(f"Process {pid} paused successfully")
        else:
            logger.error(f"Failed to pause process {pid}")
        return result

    @mcp.tool()
    def resume_process(pid: int) -> Dict[str, Any]:
        """
        Resume a paused process.

        Args:
            pid: Process ID to resume

        Returns:
            Success status of the resume operation
        """
        logger.info(f"Resuming process {pid}")
        result = bear_client.safe_post(f"api/processes/resume/{pid}", {})
        if result.get("success"):
            logger.info(f"Process {pid} resumed successfully")
        else:
            logger.error(f"Failed to resume process {pid}")
        return result

    @mcp.tool()
    def get_process_dashboard() -> Dict[str, Any]:
        """
        Get process dashboard with visual status indicators.

        Returns:
            Real-time dashboard with process status
        """
        logger.info("Getting process dashboard")
        result = bear_client.safe_get("api/processes/dashboard")
        if result.get("success", True) and "total_processes" in result:
            total = result.get("total_processes", 0)
            logger.info(f"Dashboard retrieved: {total} active processes")
        else:
            logger.error("Failed to get process dashboard")
        return result


    # ============================================================================
    # ASYNC TASK MANAGEMENT
    # ============================================================================

    @mcp.tool()
    def get_task_status(task_id: str) -> Dict[str, Any]:
        """
        Poll the status of an async task submitted with async_mode=True.

        Status values: queued / running / completed / failed / cancelled

        Args:
            task_id: Task ID returned when async_mode=True was used

        Returns:
            Task status and result (when completed or failed)
        """
        logger.info(f"Polling task status: {task_id}")
        result = bear_client.safe_get(f"api/tasks/{task_id}")
        status = result.get("status", "unknown")
        if status in ("completed", "failed"):
            runtime = result.get("result", {}).get("execution_time", 0)
            logger.info(f"Task {task_id} {status} (execution_time={runtime:.1f}s)")
        elif status == "running":
            logger.info(f"Task {task_id} still running ({result.get('runtime_seconds', 0)}s elapsed)")
        else:
            logger.info(f"Task {task_id} status: {status}")
        return result

    @mcp.tool()
    def list_async_tasks(offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """
        List a page of async tasks and their current status.

        Args:
            offset: Number of tasks to skip
            limit: Maximum number of tasks in this page

        Returns:
            Task page with status, submission time, runtime info, and pagination
        """
        logger.info("Listing async tasks")
        result = bear_client.safe_get("api/tasks", {"offset": offset, "limit": limit})
        logger.info(f"Found {result.get('total', 0)} async task(s)")
        return result

    @mcp.tool()
    def cancel_async_task(task_id: str) -> Dict[str, Any]:
        """
        Cancel a queued or running async task.

        Args:
            task_id: Task ID to cancel

        Returns:
            Cancellation result
        """
        logger.info(f"Cancelling task: {task_id}")
        result = bear_client.safe_delete(f"api/tasks/{task_id}")
        if result.get("success"):
            logger.info(f"Task {task_id} cancelled")
        else:
            logger.error(f"Failed to cancel task {task_id}: {result.get('error', '')}")
        return result

    return mcp


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="BEAR - Binary Exploitation & Automated Reversing MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_BEAR_SERVER,
                      help=f"BEAR API server URL (default: {DEFAULT_BEAR_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    """Main entry point for the MCP server."""
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    logger.info(f"Starting BEAR MCP Client v{VERSION}")
    logger.info(f"Backend configured at: {args.server} (checked only on tool requests)")

    try:
        bear_client = BearClient(args.server, args.timeout)

        mcp = setup_mcp_server(bear_client)
        logger.info("Starting BEAR MCP server")
        logger.info("Ready to serve AI agents with binary analysis capabilities")
        mcp.run()
    except Exception as e:
        logger.error(f"Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
