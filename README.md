<div align="center">

# BEAR v1.4
### Binary Exploitation & Automated Reversing

[![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2.svg)](#)

**MCP server specialized in binary analysis, reverse engineering, and exploit development tools**

</div>

---

## Overview

BEAR (Binary Exploitation & Automated Reversing) is an MCP (Model Context Protocol) server that provides AI agents with access to binary analysis and reverse engineering tools. It enables AI assistants like Claude, GPT, or Copilot to execute security tools for authorized penetration testing and CTF challenges.

The API backend is built with FastAPI and Pydantic, while the MCP layer uses standalone FastMCP.

## Features

- **Binary Analysis Tools** - GDB, Radare2, Ghidra decompile/disassembly/functions/xrefs/callgraph, Binwalk, Checksec
- **Binary Triage** - File metadata, SHA256, Checksec, ELF headers, symbols, and strings summary
- **Exploit Development** - Pwntools, ROPgadget, Ropper, One-Gadget
- **CVE Intelligence** - CVE lookup and exploit generation assistance
- **MCP Protocol** - Compatible with Claude Desktop, Cursor, VS Code Copilot

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/bear.git
cd bear

# Install dependencies with uv
uv sync --python 3.13
```

### Required Tools

Install the binary analysis tools you need:

```bash
# Core tools
sudo apt install gdb binwalk checksec strings objdump

# Optional external tools
# radare2, ghidra, pwninit, ropgadget, ropper, one_gadget
```

---

## Usage

### Start the Server

```bash
uv run bear-server
```

### MCP Client Configuration

**Claude Desktop** (`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "bear": {
      "command": "uv",
      "args": ["--directory", "/path/to/bear", "run", "bear-mcp"]
    }
  }
}
```

**VS Code / Cursor**: Add to your MCP settings with the same configuration.

---

## Project Layout

```text
bear/
  server.py          # FastAPI backend
  mcp.py             # FastMCP server wrapper
  models.py          # Pydantic request models
  ui.py              # Colors, banner, log formatting
  ghidra_scripts/    # Ghidra headless Java scripts
tests/
  test_bear_server.py
```

---

## Supported Tools

| Category | Tools |
|----------|-------|
| Debuggers | GDB, GDB-PEDA, GDB-GEF |
| Disassemblers | Ghidra, Radare2, Objdump |
| Binary Inspection | Binwalk, Checksec, Strings, Readelf |
| Ghidra Navigation | Functions, Xrefs, Call Graph |
| Triage | File, SHA256, Checksec, ELF Header, Symbols, Strings |
| Exploit Dev | Pwntools, ROPgadget, Ropper, One-Gadget |
| Utilities | XXD, Hexdump |

---

## Legal Notice

This tool is intended for:
- Authorized penetration testing
- CTF competitions
- Security research on owned systems
- Educational purposes

**Do not use on systems without explicit authorization.**

---

## License

MIT License
