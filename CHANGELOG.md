# Changelog

All notable changes to BEAR will be documented in this file.

## [1.4.0] - 2026-06-06

### Added
- `uv` project configuration via `pyproject.toml`
- Disk-backed command cache using `diskcache`
- Ghidra disassembly endpoint and MCP tool
- `disassemble_binary` MCP tool that prefers Ghidra and falls back to objdump
- Packaged project layout under `bear/`
- Shared `bear/ui.py` module for colors, log formatting, and banner rendering
- `triage_binary` API/MCP tool for quick static binary triage
- `ghidra_functions` API/MCP tool for function listing
- `ghidra_xrefs` API/MCP tool for cross-reference lookup
- `ghidra_callgraph` API/MCP tool for call graph generation
- Shared Ghidra inspection script: `InspectBinary.java`

### Changed
- MCP server now imports FastMCP from the standalone `fastmcp` package
- README and MCP config now use `uv run`
- Migrated the API backend from Flask to FastAPI
- Replaced `schema` validation with Pydantic request models
- Updated the server entry point to run with uvicorn
- Migrated API tests from Flask's test client to FastAPI `TestClient`
- Ghidra inspection tools share the same backend execution/parser path
- Console entrypoints now target `bear.server` and `bear.mcp`

### Removed
- `requirements.txt`
- angr dependency, server endpoint, MCP tool, and tests
- Flask dependency
- `schema` dependency

## [1.3.0] - 2026-01-21

### Added
- Schema validation library for endpoint parameter validation
- `tool_endpoint` decorator for consistent endpoint behavior
- `cleanup_temp_file` helper function for temp file management

### Changed
- Refactored 19 tool endpoints to use schema validation decorator
- Reduced ~350 lines of duplicate code across endpoints
- Unified error handling: SchemaError/ValueError → 400, Exception → 500
- Health check now always logs tool checks (removed verbose flag)

### Removed
- Volatility, Volatility3, MSFVenom, UPX tools and endpoints

## [1.2.0] - 2026-01-20

### Added
- Version display in server banner
- `log_as` parameter for cleaner command logging
- Success log for Ghidra decompilation

### Changed
- Improved logging format: `[LEVEL] message` style
- Silenced verbose werkzeug request logs
- All tool endpoints now use friendly log messages (e.g., "Executing: Checksec /bin/ls")
- Simplified ColoredFormatter in MCP client (removed unused emojis)
- Added VERSION constant to MCP client

### Fixed
- Removed obsolete test for non-existent `/api/tools/ghidra` endpoint

## [1.1.1] - 2026-01-19

### Added
- Version display in server banner

### Changed
- Improved Ghidra endpoint with JSON body validation

## [1.1.0] - 2026-01-17

### Added
- **Ghidra Decompilation**: New `ghidra_decompile` tool that returns C-like pseudocode
  - Decompile all functions or specific function by name/address
  - JSON structured output for easy parsing
  - Custom Ghidra script (`DecompileFunction.java`) for headless decompilation
- **Unit Tests**: Added pytest test suite for API endpoints
  - Tests for all major tools (Ghidra, GDB, Radare2, Binwalk, etc.)
  - Mocked command execution for CI/CD compatibility
- **Ghidra Auto-Discovery**: Server automatically finds Ghidra installation
  - Checks common paths and `GHIDRA_HEADLESS` environment variable

### Changed
- Improved Ghidra integration to return actual analysis results instead of just logs

### Fixed
- Ghidra headless mode now properly returns decompiled code to AI agents

## [1.0.0] - 2026-01-15

### Added
- Initial release
- MCP server with 25+ binary analysis tools
- Support for GDB, Radare2, Ghidra, Binwalk, Checksec
- Exploit development tools: Pwntools, ROPgadget, Ropper, One-Gadget
- Compatible with Claude Desktop, Cursor, VS Code
