# Changelog

All notable changes to BEAR will be documented in this file.

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
- Memory forensics: Volatility, Volatility3
- Compatible with Claude Desktop, Cursor, VS Code
