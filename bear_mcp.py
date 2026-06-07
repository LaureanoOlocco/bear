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
from typing import Dict, Any, Optional
import requests
import time

from fastmcp import FastMCP

from bear_ui import ColoredFormatter

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

class BearClient:
    """Client for communicating with the BEAR API Server"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"Attempting to connect to BEAR API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"Successfully connected to BEAR API Server at {server_url}")
                    logger.info(f"Server health status: {health_check.get('status', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"Connection refused to {server_url}. Make sure the server is running.")
                    time.sleep(2)
                except Exception as e:
                    logger.warning(f"Connection test failed: {str(e)}")
                    time.sleep(2)
            except Exception as e:
                logger.warning(f"Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)

        if not connected:
            logger.error(f"Failed to connect to BEAR API Server at {server_url} after {MAX_RETRIES} attempts")

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        url = f"{self.server_url}/{endpoint}"
        try:
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        try:
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_delete(self, endpoint: str) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        try:
            response = self.session.delete(url, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

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
    def triage_binary(binary: str, strings_limit: int = 40, use_cache: bool = True) -> Dict[str, Any]:
        """
        Run quick binary triage: file type, SHA256, checksec, ELF headers, symbols, and strings.

        Args:
            binary: Path to the binary file
            strings_limit: Maximum number of strings to include
            use_cache: Whether to use server-side command cache

        Returns:
            Triage summary and command outputs
        """
        data = {
            "binary": binary,
            "strings_limit": strings_limit,
            "use_cache": use_cache,
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
    def strings_extract(file_path: str, min_len: int = 4, encoding: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Extract printable strings from a binary file.

        Args:
            file_path: Path to the file
            min_len: Minimum string length (default: 4)
            encoding: String encoding (s=single-byte, S=single-byte+unicode, b=big-endian, l=little-endian)
            additional_args: Additional strings arguments

        Returns:
            String extraction results
        """
        data = {
            "file_path": file_path,
            "min_len": min_len,
            "encoding": encoding,
            "additional_args": additional_args
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
                           timeout: int = 300) -> Dict[str, Any]:
        """
        Disassemble a binary, preferring Ghidra and falling back to objdump.

        Args:
            binary: Path to the binary file
            function: Function name/address for Ghidra; ignored by objdump fallback
            backend: auto, ghidra, or objdump
            timeout: Ghidra analysis timeout in seconds

        Returns:
            Disassembly result with the backend used
        """
        selected = backend.lower().strip()
        if selected not in ("auto", "ghidra", "objdump"):
            return {"success": False, "error": "backend must be auto, ghidra, or objdump"}

        if selected in ("auto", "ghidra"):
            ghidra_result = ghidra_disassemble(binary=binary, function=function, timeout=timeout)
            if ghidra_result.get("success"):
                ghidra_result["backend"] = "ghidra"
                return ghidra_result
            if selected == "ghidra":
                ghidra_result["backend"] = "ghidra"
                return ghidra_result
            fallback_reason = ghidra_result.get("error", "Ghidra disassembly failed")
        else:
            fallback_reason = "backend=objdump requested"

        objdump_result = objdump_analyze(binary=binary, disassemble=True)
        objdump_result["backend"] = "objdump"
        objdump_result["fallback_reason"] = fallback_reason
        return objdump_result

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
    def execute_python_script(script: str, env_name: str = "default", filename: str = "") -> Dict[str, Any]:
        """
        Execute a Python script in a virtual environment.

        Args:
            script: Python script content to execute
            env_name: Name of the virtual environment
            filename: Custom script filename (auto-generated if empty)

        Returns:
            Script execution results
        """
        data = {
            "script": script,
            "env_name": env_name
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
    def execute_command(command: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the server.

        Args:
            command: The command to execute
            use_cache: Whether to use caching for this command

        Returns:
            Command execution results
        """
        try:
            logger.info(f"Executing command: {command}")
            result = bear_client.execute_command(command, use_cache)
            if "error" in result:
                logger.error(f"Command failed: {result['error']}")
                return {
                    "success": False,
                    "error": result["error"],
                    "stdout": "",
                    "stderr": f"Error executing command: {result['error']}"
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
    def list_async_tasks() -> Dict[str, Any]:
        """
        List all async tasks and their current status.

        Returns:
            All tasks with status, submission time, and runtime info
        """
        logger.info("Listing async tasks")
        result = bear_client.safe_get("api/tasks")
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
    logger.info(f"Connecting to: {args.server}")

    try:
        bear_client = BearClient(args.server, args.timeout)

        health = bear_client.check_health()
        if "error" in health:
            logger.warning(f"Unable to connect to server at {args.server}: {health['error']}")
            logger.warning("MCP server will start, but tool execution may fail")
        else:
            logger.info(f"Successfully connected to server at {args.server}")
            logger.info(f"Server health status: {health['status']}")

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
