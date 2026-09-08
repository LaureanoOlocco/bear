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
- **Binary Triage** - Format-aware ELF/PE checks, bounded strings, opt-in SHA256
- **PE Resources** - Native listing/extraction by type, ID and language; bounded batch jobs
- **Long Analyses** - Async tasks, cancellation, partial output and paged artifacts
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
sudo apt install gdb binwalk checksec binutils

# Optional external tools
# radare2, ghidra, pwninit, ropgadget, ropper, one_gadget
```

---

## Usage

### Start the Server

```bash
uv run bear-server
```

The backend binds to `127.0.0.1:8888`. Check it with
`curl http://127.0.0.1:8888/health`. Set `--port`/`BEAR_PORT` and
`--host`/`BEAR_HOST` to change the listener. Do not expose this unauthenticated
command-execution API to an untrusted network.

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

The MCP process registers tools without waiting for backend health. It can start
offline and use a restarted backend on subsequent calls. Connection establishment
is retried with bounded backoff; a timed-out or reset mutation request is **not**
replayed because it may already have executed. If the MCP stdio process itself
dies, the host must reconnect it. After upgrading BEAR, restart both the backend
and the client's MCP process once to load the new code and tool schemas.

### Ghidra First

Use `disassemble_binary` / `POST /api/tools/disassemble` for normal disassembly:

```json
{"binary":"/path/to/program","function":"main","backend":"auto","async_mode":true}
```

`auto` prefers Ghidra and falls back to objdump only when Ghidra is not installed,
not after an analysis failure. Explicit `objdump_analyze` remains available for
objdump-specific arguments and metadata. Set `GHIDRA_HEADLESS` to the full
`support/analyzeHeadless` path if discovery does not find your installation.

All Ghidra operations share one persistent analyzed project per binary, protected
by an OS file lock. Different functions and inspection modes reuse it with
`-process -noanalysis`; identical-binary requests are serialized. Changed binary
contents or Ghidra identity invalidate reuse, and failed imports are not published
as ready projects. Projects survive backend restarts. Ghidra still launches a JVM
per query, and content fingerprinting still reads the binary.

### Bounded Analysis

- Triage detects ELF, PE, MachO or unknown from headers. Only ELF runs ELF checks;
  PE uses native header/security metadata. Skips and failures are reported separately.
- Triage SHA256 requires `compute_hash=true`; it deliberately reads the entire file.
- Strings scan at most 16 MiB by default (`max_scan_bytes`) and return at most
  1,000 strings (`max_strings`). PE scans code/initialized-data sections, excluding
  `.rsrc`, the resource directory, headers and overlays by default.
- `offset` and optional `length` specify absolute byte windows.
  `include_resources=true` includes resource sections; `full_scan=true` opts into
  raw scanning beyond the default input budget. Output limits remain in effect.
- Native strings supports explicit encodings/options, not arbitrary `additional_args`.
  Long individual strings are limited to 4,096 characters and marked as truncated.
- `pefile` and `capstone` are installed by `uv sync`. Python script environments
  retain their own installed packages and use BEAR's packages as a fallback.

### Tasks And Artifacts

Command execution, Python execution, strings, triage, and Ghidra endpoints accept
`async_mode=true`. They immediately return a `task_id`. Poll `GET /api/tasks/{task_id}`
or the MCP `get_task_status` tool. `GET /api/tasks?offset=0&limit=50` lists summaries.
Command/Python and Ghidra subprocess `timeout` values are seconds of process
execution, not queue waiting or project fingerprinting time.

`progress_percent` is `null` for tools without measurable progress, with `stage`,
elapsed runtime and bounded stdout/stderr previews instead. Resource batches
report actual completed/total counts, percentages and partial result pages.
`DELETE /api/tasks/{task_id}` requests cancellation. `cancel_requested=true` does
not mean cleanup has finished: wait for `status=cancelled`. Cancelling or timing
out a subprocess kills its process group, including JVM children in that group.
Post-termination pipe draining is bounded: if detached processes retain pipe
handles, BEAR returns `output_incomplete=true` rather than waiting indefinitely.
Processes that detach into separate sessions are outside process-group cleanup;
BEAR is not a process sandbox.

Small JSON responses stay inline. Larger responses use an envelope:

```json
{"success":true,"truncated":true,"artifact":{"artifact_id":"...","size_bytes":90000},"preview":"..."}
```

The artifact contains the **complete original JSON**, not just the preview.
Command stdout/stderr similarly have `stdout_artifact`/`stderr_artifact` handles
when they exceed 4 KiB previews. Read artifacts with MCP `read_artifact` or
`GET /api/artifacts/{artifact_id}?offset=0&limit=8192`. Each page contains base64
`data`, byte-based `next_offset`, and `eof`; decode and concatenate bytes before
parsing JSON or text. Binary extraction uses the same lossless interface.

### PE Resources

The MCP tools `pe_resources`, `pe_resources_extract`, and `pe_resources_batch`
wrap these endpoints (resource type `10` is RCDATA):

```text
POST /api/tools/pe/resources
{"binary":"sample.exe","resource_type":10,"offset":0,"limit":100}

POST /api/tools/pe/resources/extract
{"binary":"sample.exe","resource_type":10,"resource_id":7,"language":1033}

POST /api/tools/pe/resources/batch
{"binary":"sample.exe","resource_type":10,"operation":"sha256","limit":500,"concurrency":4}
```

Resource filters accept numeric IDs or exact names. Specify a language if the ID
has multiple variants. A source can be `binary` or `artifact_id`, but not both.
Batch operations are `extract` and `sha256`, always asynchronous, with up to 500
resources per job and four workers. Use `next_offset` for subsequent selection
pages. `result_offset`/`result_limit` limit partial/final result pages, with a full
`results_artifact` when the page omits results. Extraction defaults to 64 MiB per
resource and batches to 256 MiB total; explicit limits are capped by the schema.

### Runtime Limits

| Setting | Default | Purpose |
|---------|---------|---------|
| `BEAR_TASK_WORKERS` | 4 | Concurrent async jobs |
| `BEAR_MAX_PENDING_TASKS` | 100 | Running plus queued job limit |
| `BEAR_MAX_TASKS` | 1000 | In-memory task-history cap |
| `BEAR_TASK_TTL` | 86400 | Finished-history lifetime, seconds; pruned on submission |
| `BEAR_MAX_OUTPUT_BYTES` | 268435456 | Combined subprocess stdout/stderr cap |
| `BEAR_MAX_ARTIFACT_BYTES` | 268435456 | Maximum single artifact size |
| `BEAR_ARTIFACT_DIR` | `.bear_artifacts` | Persistent output storage |
| `BEAR_GHIDRA_PROJECT_DIR` | `/var/tmp/bear_ghidra_projects_<uid>` | Persistent analyzed projects |

Ghidra project paths must not contain hidden (`.name`) components. Artifact and
project retention is manual: stop BEAR and clear artifacts together with command
caches when old handles are no longer needed. Projects may be removed while BEAR
is stopped to reclaim disk; subsequent calls reanalyze. No total disk quota or
automatic project eviction is implemented. Task state is in-memory, does not
survive restarts, and requires a single API worker (the default). Already-running
tasks are cancelled on graceful backend shutdown, not resumed afterward.

Logs record command return codes, timeout flags, execution time, Ghidra outcomes
and task IDs/status. HTTP `200` alone still does not mean the underlying tool
succeeded: inspect the response's `success` field.

---

## Project Layout

```text
bear/
  server.py          # FastAPI backend
  mcp.py             # FastMCP server wrapper
  models.py          # Pydantic request models
  analysis.py        # Bounded native analysis and PE resources
  artifacts.py       # Lossless paged outputs
  ghidra.py          # Persistent project lifecycle and locking
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
