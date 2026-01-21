# Changelog

All notable changes to BEAR will be documented in this file.

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
