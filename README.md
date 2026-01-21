<div align="center">

<p align="center">
  <img src="assets/bear-logo.png" width="400" alt="BEAR logo">
</p>

# BEAR v1.3
### Binary Exploitation & Automated Reversing

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-8A2BE2.svg)](#)

**MCP server specialized in binary analysis, reverse engineering, and exploit development tools**

</div>

---

## Overview

BEAR (Binary Exploitation & Automated Reversing) is an MCP (Model Context Protocol) server that provides AI agents with access to binary analysis and reverse engineering tools. It enables AI assistants like Claude, GPT, or Copilot to execute security tools for authorized penetration testing and CTF challenges.

## Features

- **Binary Analysis Tools** - GDB, Radare2, Ghidra, Binwalk, Checksec
- **Exploit Development** - Pwntools, ROPgadget, Ropper, One-Gadget
- **CVE Intelligence** - CVE lookup and exploit generation assistance
- **MCP Protocol** - Compatible with Claude Desktop, Cursor, VS Code Copilot

---

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/bear.git
cd bear

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac

# Install dependencies
pip3 install -r requirements.txt
```

### Required Tools

Install the binary analysis tools you need:

```bash
# Core tools
sudo apt install gdb binwalk checksec strings objdump

# Optional
# radare2, ghidra, pwntools (pip install pwntools)
```

---

## Usage

### Start the Server

```bash
python3 bear_server.py
```

### MCP Client Configuration

**Claude Desktop** (`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "bear": {
      "command": "python3",
      "args": ["/path/to/bear/bear_mcp.py"]
    }
  }
}
```

**VS Code / Cursor**: Add to your MCP settings with the same configuration.

---

## Supported Tools

| Category | Tools |
|----------|-------|
| Debuggers | GDB, GDB-PEDA, GDB-GEF |
| Disassemblers | Radare2, Ghidra, Objdump |
| Binary Inspection | Binwalk, Checksec, Strings, Readelf |
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

