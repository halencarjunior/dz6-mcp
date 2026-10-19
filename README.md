# dz6-mcp

<p align="center">
  <img src="DZ6MCP.png" alt="dz6-mcp logo" width="720">
</p>

[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![MCP: stdio](https://img.shields.io/badge/MCP-stdio-6f42c1.svg)](https://modelcontextprotocol.io/)

[English](README.md) | [Português (Brasil)](README.pt-BR.md)

A [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes
the [dz6](https://dz6.dev.br) terminal hex editor to any MCP-capable harness.

`dz6-mcp` speaks MCP over **stdio** and reuses dz6 itself as its engine, so it
has the same mmap-backed file access, the same PE/ELF parser (goblin), the same
search syntax and the same annotation model, just without a terminal.

- **Inspect**: metadata, bytes, integers, strings, entropy, hex dumps, PE/ELF
  headers, sections, segments, symbols, imports/exports, notes and directories.
- **Search**: literal text and hex, dz6 wildcards, and a signature engine with
  nibble wildcards, gaps, alternation, masked patterns and named pattern sets.
- **Translate**: PE VA/RVA and ELF virtual addresses to file offsets and back.
- **Edit**: staged byte patches, fills, undo, save and truncate.
- **Annotate**: comments, bookmarks and colored blocks, persisted to dz6's
  `<file>.dz6` TOML sidecar.
- **Diagnose**: server metadata, runtime log level and an in-memory log tail.

Nothing is written to the target file until you call `save` (with the sole
exception of the explicitly destructive `truncate`).

---

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Requirements](#requirements)
- [Build and install](#build-and-install)
- [Command-line options](#command-line-options)
- [Harness configuration](#harness-configuration)
- [Core concepts](#core-concepts)
- [Tool reference](#tool-reference)
  - [Files](#files)
  - [Reading and analysis](#reading-and-analysis)
  - [Binary inspection](#binary-inspection)
  - [Editing](#editing)
  - [Annotations](#annotations)
  - [Diagnostics](#diagnostics)
- [Search syntax](#search-syntax)
- [Pattern scanning](#pattern-scanning)
- [PE/ELF reference](#peelf-reference)
- [Workflows](#workflows)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [FAQ](#faq)
- [License](#license)

---

## How it works

```text
MCP client (Claude, Codex, OpenCode, …)
        │  JSON-RPC 2.0 over stdio
        ▼
dz6-mcp ── state: one dz6 App per open file
        │            ├─ mmap of the file
        │            ├─ staged edits (in memory)
        │            └─ comments / bookmarks / blocks
        ▼
target file on disk          <file>.dz6 sidecar
```

- stdout carries **only** JSON-RPC. Logs and the startup banner go to stderr.
- Files are opened **lazily** by any tool that takes a `path`, then cached for
  the lifetime of the session.
- Reads, searches and analysis run against the **effective bytes**: the mmap
  overlaid with staged edits.
- Structural parsing (`headers`, `sections`, `symbols`, `pe_info`, `elf_info`)
  reads the on-disk mapping and therefore reflects the file as saved.
- `save` flushes staged edits and the annotation sidecar.

## Quick start

```sh
# 1. Prepare the patched dz6 dependency (see Requirements below), then build
cargo build --release --locked

# 2. Point your MCP client at the binary (absolute path)
#    /absolute/path/to/dz6-mcp/target/release/dz6-mcp

# 3. Use it from the client, for example:
#    "Use dz6 to open /bin/true, list its sections and show the interpreter."
```

A minimal client configuration looks like this:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/absolute/path/to/dz6-mcp/target/release/dz6-mcp",
      "args": ["--readonly"]
    }
  }
}
```

Drop `--readonly` when the client should be able to stage and save edits.

## Requirements

- Rust 1.89 or newer (edition 2024 and locked dependency requirements).
  Validated locally with Rust 1.99.1.
- A dz6 checkout that exposes a **library target**. Upstream dz6 ships as a
  binary, so the checkout must provide:

  1. `src/lib.rs` re-exporting dz6's modules (`pub mod app; pub mod hex; …`)
     plus the `beep!` macro and `update_page_size`.
  2. `src/main.rs` consuming the library crate instead of declaring the modules.
  3. `beep!` writing its terminal bell to **stderr** (`eprint!`), so stdout is
     reserved for the MCP protocol.

  These changes are source-compatible with the TUI. The server depends on dz6 as
  a path dependency:

  ```toml
  dz6 = { path = "../dz6" }
  ```

  This repository includes the required changes in
  [`patches/dz6-library.patch`](patches/dz6-library.patch). From the directory
  where you want both checkouts, run:

  ```sh
  git clone https://github.com/halencarjunior/dz6-mcp.git
  git clone https://github.com/mentebinaria/dz6.git
  git -C dz6 checkout --detach 9612897db2b0c5ec75ea92285b183e1062ba9af9
  git -C dz6 apply --check ../dz6-mcp/patches/dz6-library.patch
  git -C dz6 apply ../dz6-mcp/patches/dz6-library.patch
  cd dz6-mcp
  cargo build --release --locked
  ```

  Use a fresh dz6 checkout for these commands. The patch is tied to the exact
  commit above; it adds a library target, adapts the TUI entrypoint and moves
  its bell to stderr. No dz6 changes need to be published separately.
  `cargo install --git` and crates.io installation are not supported while the
  server uses this sibling path dependency.

  To validate changes before pushing:

  ```sh
  cargo fmt --check
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked
  ```

## Build and install

```sh
cargo build --release
# binary: target/release/dz6-mcp
```

Install it somewhere on `PATH`:

```sh
cargo install --path .
# or
install -m 0755 target/release/dz6-mcp ~/.local/bin/dz6-mcp
```

Verify the build without a client:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"example","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | ./target/release/dz6-mcp 2>/dev/null
```

The last response should advertise 39 tools.

## Command-line options

```text
dz6-mcp [OPTIONS]

  --readonly               Open every file read-only; write tools return an error
  -v, --verbose...         Increase verbosity: -v info, -vv debug, -vvv trace
      --log-level FILTER   EnvFilter directive (overrides -v and RUST_LOG)
      --log-file PATH      Also append logs to PATH
  -h, --help               Print help
  -V, --version            Print version
```

Filter precedence: `--log-level` > `RUST_LOG` > `-v` > default `warn`.
`--log-level` accepts a level (`trace`, `debug`, `info`, `warn`, `error`,
`off`) or a directive list such as `dz6_mcp=debug,rmcp=info`.

On startup stderr shows:

```text
dz6-mcp 0.1.0 (pid 12345) — stdio transport, read-write mode
log level: warn (change with --log-level, RUST_LOG or the log_level tool); log file: none
```

Per-call logs (tool name, elapsed milliseconds, error status) are emitted at
`info`. The last 2000 lines are always kept in memory and can be read with the
`logs_tail` tool, because most MCP clients do not surface the server's stderr.

## Harness configuration

Every harness below runs `dz6-mcp` as a local **stdio** server, so the only
thing they all need is the absolute path to the binary:

```sh
cargo build --release
# /absolute/path/to/dz6-mcp/target/release/dz6-mcp
```

Add `--readonly` to the arguments if you only want to inspect files. The tools
also carry MCP read-only annotations, so clients with an approval system can
auto-approve reads and ask for approval before edits. `truncate` additionally
carries `destructive_hint`.

> **Important:** `command` must point at the **executable**, not at a directory.
> Pointing it at `.../target/release` is the most common cause of "server not
> connected" errors.

| Harness | Configuration |
| --- | --- |
| [Claude Desktop](#claude-desktop) | `claude_desktop_config.json` |
| [Claude Code](#claude-code) | `claude mcp add`, `.mcp.json` or `~/.claude.json` |
| [OpenAI Codex](#openai-codex) | `~/.codex/config.toml` (`[mcp_servers.dz6]`) |
| [DeepSeek Harness (dsh)](#deepseek-harness-dsh) | `$DSH_HOME/profiles/<profile>/cordis.patch.yml` |
| [OpenCode](#opencode) | `opencode.jsonc` (`mcp.servers`) |
| [Kilo Code](#kilo-code) | `kilo.jsonc` (`mcp`), legacy `mcp_settings.json` |
| [Pi](#pi) | `~/.pi/agent/mcp.json` or `.pi/mcp.json` (`mcpServers`) |
| [Cursor / VS Code](#cursor--vs-code--generic-clients) | client MCP settings |
| [Raw stdio](#raw-stdio) | spawn the process and speak JSON-RPC |

After editing any configuration, restart the client (or reload its MCP
connections). Tool lists are usually cached per session, so a rebuilt server
with new tools will not appear until the session reconnects.

### Claude Desktop

Add the server to `claude_desktop_config.json` and restart the app:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

### Claude Code

The CLI writes the config for you:

```sh
claude mcp add dz6 -- /path/to/dz6-mcp                 # local scope (default)
claude mcp add --scope user dz6 -- /path/to/dz6-mcp    # all projects
claude mcp add --scope project dz6 -- /path/to/dz6-mcp # shared via .mcp.json
claude mcp list
claude mcp get dz6
```

Or edit the file directly: `.mcp.json` at the project root (project scope,
meant to be committed) or the top-level `mcpServers` key in `~/.claude.json`
(user scope):

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

Run `/mcp` inside a session to check the connection and approve project-scoped
servers.

### OpenAI Codex

Codex reads `~/.codex/config.toml`, or a project-scoped `.codex/config.toml`
in trusted projects. Add a server with either the CLI:

```sh
codex mcp add dz6 -- /path/to/dz6-mcp
codex mcp list
codex mcp get dz6
```

or directly in `config.toml`:

```toml
[mcp_servers.dz6]
command = "/path/to/dz6-mcp"
args = []
startup_timeout_sec = 10
tool_timeout_sec = 60
```

For a read-only session:

```toml
[mcp_servers.dz6]
command = "/path/to/dz6-mcp"
args = ["--readonly"]
```

Because the tools advertise read-only annotations, Codex can auto-approve reads
and ask before edits:

```toml
[mcp_servers.dz6]
command = "/path/to/dz6-mcp"
default_tools_approval_mode = "writes"   # auto: reads; prompt: writes
```

Inside the TUI, run `/mcp` to confirm the server is connected. The IDE
extension shares the same configuration. See the
[Codex MCP docs](https://developers.openai.com/codex/mcp) for per-tool approval
overrides and tool allow/deny lists.

### DeepSeek Harness (dsh)

DeepSeek Harness wires MCP servers through its plugin tree. Add one
`@deepseek-ai/dsh-mcp-client` row per server to the active profile patch,
`$DSH_HOME/profiles/<profile>/cordis.patch.yml` (default `$DSH_HOME` is
`~/.dsh`), or to the home-level `cordis.patch.yml`:

```yaml
- id: dz6
  name: '@deepseek-ai/dsh-mcp-client'
  config:
    serverName: dz6
    transport: stdio
    command: /path/to/dz6-mcp
    args: []
    toolCallTimeoutMs: 30000
```

For a one-off overlay without editing the profile:

```sh
dsh web --patch ./dz6.cordis.yml
```

The server's tools reach the model as `mcp__dz6__open_file`,
`mcp__dz6__read_bytes`, and so on. Restart the profile after changing the
patch. See the [MCP client package README](https://github.com/deepseek-ai/deepseek-harness/blob/master/packages/mcp/mcp-client/README.md)
for `failOnStartupError`, `reconnect` and other fields.

### OpenCode

MCP servers live under `mcp.servers` in `opencode.jsonc` (global
`~/.config/opencode/opencode.jsonc`, or the project root). Use `disabled: true`
to keep a server configured without connecting it (there is no `enabled`
field):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "dz6": {
        "type": "local",
        "command": ["/path/to/dz6-mcp"]
      }
    }
  }
}
```

Or from the CLI (add `--global` to make it available in every project):

```sh
opencode mcp add dz6 -- /path/to/dz6-mcp
opencode mcp add --global dz6 -- /path/to/dz6-mcp
opencode mcp list
```

Under the default Code Mode, tools are grouped as `tools.dz6.<tool>(...)`; set
`"codemode": false` on the server if you want them exposed directly.

### Kilo Code

Kilo reads JSONC config: `~/.config/kilo/kilo.jsonc` (global) and `kilo.jsonc`
or `.kilo/kilo.jsonc` (project, takes precedence). Servers go under the
top-level `mcp` key:

```jsonc
{
  "mcp": {
    "dz6": {
      "type": "local",
      "command": ["/path/to/dz6-mcp"],
      "enabled": true
    }
  }
}
```

In the VS Code extension you can also use **Settings → MCP → Add Server**. The
legacy extension reads `mcp_settings.json` (global) and `.kilocode/mcp.json`
(project) with the `mcpServers` shape:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": [],
      "disabled": false
    }
  }
}
```

### Pi

The CLI writes the config for you:

```sh
pi mcp add dz6 -- /path/to/dz6-mcp       # user scope (default)
pi mcp add -l dz6 -- /path/to/dz6-mcp    # project scope (trusted projects)
pi mcp list
```

Or edit `~/.pi/agent/mcp.json` (user) or `.pi/mcp.json` (project), using the
same shape as Claude and Cursor:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

Use `/mcp` in a session to inspect connections and `/reload` after editing the
file. Project configuration is only read once the project is trusted.

### Cursor / VS Code / generic clients

Cursor, Windsurf, Cline and similar clients use an `mcpServers` object:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/path/to/dz6-mcp",
      "args": ["--readonly"]
    }
  }
}
```

VS Code uses a top-level `servers` object in `.vscode/mcp.json` (or the
`mcp.servers` section of `settings.json`):

```json
{
  "servers": {
    "dz6": {
      "type": "stdio",
      "command": "/path/to/dz6-mcp",
      "args": []
    }
  }
}
```

### Raw stdio

Any client that can spawn a process and exchange newline-delimited JSON-RPC 2.0
messages works. The sequence is `initialize` → `notifications/initialized` →
`tools/list` / `tools/call`.

```python
#!/usr/bin/env python3
import json, subprocess

p = subprocess.Popen(
    ["/path/to/dz6-mcp", "--readonly"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
)

def call(msg):
    p.stdin.write(json.dumps(msg) + "\n")
    p.stdin.flush()
    return json.loads(p.stdout.readline())

call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "example", "version": "1"},
}})
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
p.stdin.flush()

print(call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
    "name": "sections",
    "arguments": {"path": "/bin/true"},
}}))
```

The server echoes the protocol version offered by the client. Supported
versions are `2024-11-05`, `2025-03-26` and `2025-06-18`.

## Core concepts

### Sessions and lazy open

Each MCP connection owns a `ServerState` with a map of canonical path →
`dz6::App`. The first tool that mentions a path opens it; later calls reuse the
same document, including its staged edits, cursor and annotations. Use
`open_file` when you need to choose the read-only mode explicitly,
`list_open_files` to see what is cached, and `close_file` to drop it.

Multiple files can be open at once. There is no per-session file limit.

### Read-only modes

Read-only can be set in two places:

1. **Server-wide**: `dz6-mcp --readonly` makes every lazily opened file
   read-only.
2. **Per file**: `open_file` accepts `"readonly": true|false` and overrides the
   server default for that document.

If a document is already open with a different requested mode, `open_file`
reopens it, but only when it has no pending edits. The effective mode can be
stricter than requested: if the process cannot open the file for writing (for
example, a read-only file or a missing permission), the document is read-only
anyway. `file_info` reports the effective value.

Read-only documents reject `write_bytes`, `fill`, `save` and `truncate`; `undo`
is harmless because nothing can be staged. Annotations can still be staged in
memory (they are not file writes), but they cannot be persisted until the
document is reopened writable and saved. `dump` still writes to its own
`out_path`, and `log_level` / `logs_clear` still work.

### Effective bytes and staged edits

Edits are staged in dz6's in-memory `changed_bytes` map. They are visible
immediately to:

- `read_bytes`, `read_int`, `read_string`
- `search`, `search_all`
- `pattern_scan`
- `analyze`
- `dump`
- `read_at_address`

Only `save` writes them to disk. `undo` reverts staged edits newest-first.
`truncate` is the exception: it modifies the file immediately.

`strings` is the one analysis tool that scans the on-disk mapping rather than
the overlay.

Structural tools (`headers`, `sections`, `symbols`, `address_translate`,
`pe_info`, `elf_info`) parse the file as it exists on disk. Header edits staged
but not saved are not reflected there.

### Annotations and the sidecar

Comments, bookmarks and colored blocks live in the document and are written to
`<file>.dz6` (TOML) when `save` runs, provided dz6's database is enabled (it is
by default). Closing a document without saving discards unsaved annotations.
The sidecar is the same format the TUI uses, so annotations are shared with
interactive dz6 sessions.

### Numeric conventions

- **Inputs**: offsets and lengths are JSON numbers (decimal). Addresses in
  `address_translate` and `read_at_address` are strings and accept decimal or
  `0x`-prefixed hex (`"0x401000"`). Hex byte data accepts spaces and the
  separators `:`, `-`, `_`, with an optional `0x` prefix.
- **Outputs**: offsets and addresses appear both as decimal fields (`offset`,
  `start`, `end`) and as hex strings (`offset_hex`, `start_hex`, `va`,
  `file_offset_hex`, …). Hex dumps are uppercase with spaces between bytes.
- **Truncation**: `read_bytes`, `read_string`, `analyze` and `read_at_address`
  report `truncated`/actual lengths when the requested range exceeds the file
  or the internal cap.

### Results and errors

Tools return JSON objects. Successful results use MCP structured content (the
same JSON is also available as text for clients that do not read
`structuredContent`). Errors set `isError: true` and return a structured object:

```json
{ "error": "offset 0x100 is past end of file (0xff)" }
```

Error messages are meant to be actionable: they name the offending parameter
and the valid range or alternative.

## Tool reference

**39 tools**, grouped below. `RO` marks tools that advertise
`read_only_hint = true`; clients can use that for auto-approval. `truncate`
also advertises `destructive_hint = true`.

At a glance:

- **Files (5)**: `open_file`, `close_file`, `list_open_files`, `file_info`,
  `goto`
- **Reading and analysis (10)**: `read_bytes`, `read_int`, `read_string`,
  `headers`, `search`, `search_all`, `pattern_scan`, `strings`, `analyze`,
  `dump`
- **Binary inspection (6)**: `sections`, `symbols`, `address_translate`,
  `read_at_address`, `pe_info`, `elf_info`
- **Editing (5)**: `write_bytes`, `fill`, `undo`, `save`, `truncate`
- **Annotations (9)**: `comment_set`, `comments_list`, `bookmark_add`,
  `bookmark_remove`, `bookmarks_list`, `bookmark_clear`, `block_add`,
  `blocks_list`, `block_clear`
- **Diagnostics (4)**: `server_info`, `log_level`, `logs_tail`, `logs_clear`

### Files

| Tool | RO | Parameters | Returns |
| --- | --- | --- | --- |
| `open_file` | ✓ | `path`, `readonly?` | `{opened, file}` with metadata. Reopens with the requested mode when it differs and the document is clean. |
| `close_file` | – | `path`, `save?` | `{closed, path}`. `save=true` flushes staged edits first; default discards them. |
| `list_open_files` | ✓ | – | `{count, files[]}` for every cached document. |
| `file_info` | ✓ | `path` | Size, detected type, read-only state, dirty flag, pending changes, cursor and annotation counts. |
| `goto` | ✓ | `path`, `offset` | Moves the editor cursor; returns `{offset, file_size}`. `offset` must be `< size`. |

`file_info` / `list_open_files` entries contain:

```json
{
  "path": "/abs/path",
  "size": 35664,
  "size_hex": "0x8b50",
  "type": "ELF",
  "readonly": false,
  "dirty": false,
  "pending_changes": 0,
  "offset": 0,
  "bookmarks": 0,
  "comments": 0,
  "blocks": 0
}
```

The cursor set by `goto` is the default start for forward `search` calls.

### Reading and analysis

| Tool | RO | Parameters | Returns |
| --- | --- | --- | --- |
| `read_bytes` | ✓ | `path`, `offset`, `length?`, `format?`, `include_bytes?` | Hex and/or ASCII rendering plus range metadata. |
| `read_int` | ✓ | `path`, `offset`, `size`, `signed?`, `endian?` | Decimal value and raw bytes. |
| `read_string` | ✓ | `path`, `offset`, `encoding?`, `max_length?`, `stop_at_nul?` | Decoded text, byte length and character length. |
| `headers` | ✓ | `path` | Full PE or ELF header dump from dz6's parser. |
| `search` | ✓ | see [Search syntax](#search-syntax) | First matching offset (or `found: false`). |
| `search_all` | ✓ | see [Search syntax](#search-syntax) | Up to `max` matching offsets, decimal and hex. |
| `pattern_scan` | ✓ | see [Pattern scanning](#pattern-scanning) | Every match of one or more named signatures, with context. |
| `strings` | ✓ | `path`, `min_length?`, `max?`, `regex?`, `offset?`, `length?` | Printable ASCII runs, optionally regex-filtered and range-limited. |
| `analyze` | ✓ | `path`, `offset?`, `length?` | Shannon entropy, printable ratio and unique-byte count. |
| `dump` | – | `path`, `out_path`, `offset`, `length` | Writes the range to `out_path`; returns `{bytes_written}`. |

Details and limits:

- **`read_bytes`**, `length` defaults to 256 and is capped at 1 MiB.
  `format` is `both` (default), `hex` or `ascii`. `include_bytes=true` adds a
  JSON array of byte values. The length is clamped to the end of the file;
  `truncated` is true when fewer bytes than requested were available. An
  offset past EOF is an error. Reflects staged edits.
- **`read_int`**, `size` must be `1`, `2`, `4` or `8`. `endian` accepts
  `little`/`le` (default) or `big`/`be`. `signed` defaults to false. Errors if
  the integer would cross the end of the file. Reflects staged edits.
- **`read_string`**, `encoding` is `utf8` (default), `latin1`, `utf16le` or
  `utf16be`. `max_length` defaults to 256 and is capped at 1 MiB.
  `stop_at_nul` defaults to true. Invalid sequences are replaced, not rejected.
- **`headers`**, returns dz6's nested header view:
  - PE: `dos_header`, `coff_header`, `optional_header` (including data
    directories), `sections`, `imports` and `exports`.
  - ELF: `class`, `endianness`, `header`, `program_headers`, `sections`,
    `symbols`, `dynamic_symbols` and `relocations`.
  - Other formats: `{format, parsed: false, message}` instead of an error, so
    it is safe to probe unknown files.
- **`strings`**, scans printable ASCII runs (`is_ascii_graphic()` or space)
  with a minimum length of 4 by default. `regex` is **case-insensitive**.
  `max` defaults to 3000. `offset`/`length` filter by string start offset.
  Scans the on-disk mapping, not staged edits.
- **`analyze`**, entropy is Shannon entropy in bits per byte (0–8).
  `printable_ratio` is the fraction of printable bytes (0–1). `unique_bytes`
  is the number of distinct byte values (0–256). Defaults to the rest of the
  file, capped at 64 MiB. Reflects staged edits.
- **`dump`**, writes the effective range (including staged edits) to
  `out_path`. `length` must be greater than zero. The destination is created or
  overwritten with `std::fs::write`; parent directories are not created.

Example: read and decode an integer.

```json
{ "path": "/tmp/sample.bin", "offset": 0, "size": 2, "endian": "little" }
```

```json
{
  "path": "/tmp/sample.bin",
  "offset": 0,
  "size": 2,
  "signed": false,
  "endian": "little",
  "decimal": "23117",
  "raw_hex": "4D 5A"
}
```

### Binary inspection

These tools parse the executable with goblin. They return an error for files
that are neither PE nor ELF; use `headers` if you want a `parsed: false`
result instead.

| Tool | RO | Parameters | Returns |
| --- | --- | --- | --- |
| `sections` | ✓ | `path` | Sections (PE/ELF) and program headers (ELF) with addresses, offsets, flags, entropy and owning segment. |
| `symbols` | ✓ | `path`, `name_regex?`, `kind?`, `dynamic_only?`, `global_only?`, `max?` | ELF `.symtab`/`.dynsym` or PE exports/imports. |
| `address_translate` | ✓ | `path`, `address?` **or** `offset?`, `kind?` | Address ↔ file offset, plus RVA/section/segment. |
| `read_at_address` | ✓ | `path`, `address`, `kind?`, `length?`, `format?`, `include_bytes?` | Bytes at a VA/RVA, reflecting staged edits. |
| `pe_info` | ✓ | `path` | PE directories and metadata (PDB, TLS, certificates, resources, CLR, Rich header, overlay, …). |
| `elf_info` | ✓ | `path` | ELF interpreter, dynamic tags, NEEDED/SONAME/RPATH/RUNPATH, notes and segments. |

#### `sections`

For PE, each section reports:

```json
{
  "name": ".text",
  "virtual_address": "0x1000",
  "virtual_size": "0x7fa10",
  "va_start": "0x140001000",
  "va_end": "0x140080a10",
  "file_offset": "0x400",
  "file_size": "0x7fc00",
  "entropy": 6.21,
  "characteristics": "0x60000020",
  "flags": {
    "readable": true, "writable": false, "executable": true,
    "code": true, "initialized_data": false, "uninitialized_data": false
  }
}
```

For ELF, each section adds `type`, `type_name`, `alloc`, `writable`,
`executable`, `addr`, `offset`, `size`, `addralign`, `entsize` and the index of
the owning `segment`. The response also includes `segments[]` with
`type_name` (`LOAD`, `DYNAMIC`, `INTERP`, `NOTE`, …), decoded `readable` /
`writable` / `executable`, `offset`, `vaddr`, `paddr`, `filesz`, `memsz` and
`align`. Entropy is computed over the raw section bytes.

#### `symbols`

Common parameters:

- `name_regex`, Rust regex matched against the symbol name.
- `kind`, `all` (default), `function`, `object`, `import`, `export`
  (aliases: `func`, `data`, `undefined`, `defined`).
- `dynamic_only`, ELF: force `.dynsym` even when `.symtab` exists.
- `global_only`, ELF: drop local symbols.
- `max`, default 1000, capped at 10000. `truncated` reports whether more
  matches existed.

ELF behaviour: unless `dynamic_only` is set, `.symtab` is used when present
(it normally contains `.dynsym` entries too); otherwise `.dynsym` is used.
Entries include `name`, `source` (`symtab`/`dynsym`), `kind`
(`import`/`export`/`local`), `value`, `size`, `type` (`FUNC`, `OBJECT`, …),
`bind` (`LOCAL`, `GLOBAL`, `WEAK`, …), `visibility`, `shndx`, `section` and
`file_offset` when the address maps to a file range.

PE behaviour: only `all`, `import` and `export` are meaningful. Asking for
`function` or `object` returns an explanatory error. Import entries include
`dll`, `ordinal`, `rva` and `file_offset`; export entries include `rva`, `va`,
`file_offset` and `size`.

#### `address_translate`

Provide exactly one of `address` (string, decimal or `0x` hex) or `offset`
(number):

```json
{ "path": "/tmp/sample.exe", "address": "0x140001000" }
```

```json
{
  "format": "PE",
  "input": { "kind": "va", "value": "0x140001000" },
  "mapped": true,
  "file_offset": 1024,
  "file_offset_hex": "0x400",
  "va": "0x140001000",
  "rva": "0x1000",
  "section": ".text",
  "segment": null
}
```

- PE: `kind` is `va` (default) or `rva`. RVA is resolved through the section
  table (or direct for the headers region).
- ELF: `kind` must be `va`; RVA input is rejected. Mapping uses `PT_LOAD`
  segments with `p_filesz`, falling back to sections that carry an address
  (unusual layouts without program headers).
- Unmapped inputs return an error rather than a misleading `mapped: false`.

#### `read_at_address`

Combines `address_translate` with `read_bytes`:

```json
{ "path": "/tmp/sample.exe", "address": "0x140001000", "kind": "rva", "length": 32 }
```

`length` defaults to 256 and is capped at 1 MiB. `format` is `both` (default),
`hex` or `ascii`. The response includes the translation fields plus `hex`,
`ascii`, `length`, `requested_length` and `truncated`. Reads use the effective
bytes, so staged patches are visible before saving.

#### `pe_info`

Returns PE-only metadata in one object:

| Field | Contents |
| --- | --- |
| `is_64`, `is_dll`, `machine`, `machine_id` | Architecture and image type. |
| `image_base`, `entry_point_rva`, `entry_point_va` | Load addresses. |
| `checksum`, `size_of_image`, `subsystem`, `dll_characteristics` | Optional-header values. |
| `data_directories[]` | `index`, `name` (export, import, resource, exception, certificate, base_relocation, debug, architecture, global_ptr, tls, load_config, bound_import, iat, delay_import, clr_runtime), `virtual_address`, `va`, `size`. |
| `debug` | CodeView PDB70/PDB20 (`format`, `guid` or `signature`, `age`, `path`) plus `vcfeature`, `extended_dll_characteristics`, `reproducible_build`, `pogo` booleans. |
| `tls` | Raw data range, index address, callbacks address, callbacks (`va[]`), slot, zero-fill size, characteristics. |
| `exceptions` | `{function_count}` from the exception directory (`.pdata`). |
| `relocations` | `{block_count}` from the base relocation directory. |
| `load_config` | Size, security cookie, SE handler table/count, guard flags, CF function count and CF check pointer. |
| `certificates[]` | `length`, `revision`, `type` and `bytes` for each Authenticode entry. |
| `resources` | Named/id entry counts and whether version info and a manifest are present. |
| `clr` | .NET runtime version, flags, metadata RVA/size, entry point token/RVA, strong-name signature size. |
| `rich_header` | Decoded `key` and `entries[]` (`product_id`, `build`, `count`). |
| `overlay` | `offset`, `size` and `entropy` when data follows the last section. |

The tool reports **presence**, not trust: certificates are not validated, and
the Rich header is simply decoded.

#### `elf_info`

Returns ELF-only metadata:

| Field | Contents |
| --- | --- |
| `class`, `endianness`, `object_type`, `machine`, `machine_id` | ELF identity (`ELF32`/`ELF64`, `REL`/`EXEC`/`DYN`/`CORE`). |
| `entry_point`, `interpreter` | Entry address and `PT_INTERP` path. |
| `soname`, `needed`, `rpath`, `runpath` | Dynamic-linking metadata, also repeated inside `dynamic`. |
| `notes[]` | `name`, `type`, `type_name`, `description_hex`, `description_ascii`; includes the GNU build-id and ABI tag when present. |
| `dynamic` | `flags`, `flags_1`, `init`, `fini`, `init_array`, `fini_array`, `rela`, `rel`, `pltgot`, `textrel`, version definition/requirement counts, and up to 256 raw `{tag, value}` entries (`entries_truncated` flags the cap). |
| `segments[]` | Program headers with decoded type and R/W/X flags. |

### Editing

Edits are staged in memory and become visible to every read tool immediately.
Only `save` writes them to disk. `truncate` is immediate.

| Tool | RO | Parameters | Returns |
| --- | --- | --- | --- |
| `write_bytes` | – | `path`, `offset`, `data` | `{bytes_written, pending_changes, saved: false}`. |
| `fill` | – | `path`, `offset`, `length`, `value?` or `kind?` | Filled length, byte value, pending changes. |
| `undo` | – | `path`, `steps?` | Number of edits reverted and remaining pending changes. |
| `save` | – | `path` | `{bytes_written, database_saved, pending_changes, file_size}`. |
| `truncate` | – (destructive) | `path`, `offset`, `mode` | New size. Immediate and irreversible. |

- **`write_bytes`**, `data` is hex; spaces, `:`, `-` and `_` are ignored, and
  an optional `0x` prefix is accepted. The patch may cross section boundaries
  but not the end of the file.
- **`fill`**, `kind` is `zero` (0x00) or `nop` (0x90). When both `kind` and
  `value` are present, `kind` wins. `length` must be greater than zero.
- **`undo`**, reverts the most recent staged edits first. It does not revert
  `truncate` (which has already changed the file).
- **`save`**, applies staged edits to the file and then writes the `.dz6`
  sidecar. Returns the number of staged byte positions that were flushed and
  whether the database was saved. No backup file is created.
- **`truncate`**, `mode: "after"` keeps bytes through `offset` inclusive;
  `mode: "before"` drops everything before `offset` and shifts the tail to 0.
  Requires write access and **no pending edits**. Irreversible.

Typical patch loop:

```text
write_bytes {"path": "/tmp/app.exe", "offset": 4096, "data": "90 90 90"}
read_bytes  {"path": "/tmp/app.exe", "offset": 4096, "length": 8}
undo        {"path": "/tmp/app.exe"}
# or, when the patch is right:
save        {"path": "/tmp/app.exe"}
```

### Annotations

Persisted to `<file>.dz6` when `save` runs (dz6's database is enabled by
default). The sidecar is shared with the TUI.

| Tool | RO | Parameters | Returns |
| --- | --- | --- | --- |
| `comment_set` | – | `path`, `offset`, `comment` | Sets/replaces a comment; an empty string removes it. |
| `comments_list` | ✓ | `path` | Comments sorted by offset, with decimal and hex offsets. |
| `bookmark_add` | – | `path`, `offset` | Adds a bookmark (max 8); duplicates return `already_bookmarked`. |
| `bookmark_remove` | – | `path`, `offset?` | Removes one bookmark, or the most recent when `offset` is omitted. |
| `bookmarks_list` | ✓ | `path` | All bookmarks, decimal and hex. |
| `bookmark_clear` | – | `path` | Removes every bookmark. |
| `block_add` | – | `path`, `start`, `end`, `bg_color?`, `fg_color?` | Marks an inclusive byte range. |
| `blocks_list` | ✓ | `path` | All colored blocks with `0x00RRGGBB` colors. |
| `block_clear` | – | `path` | Removes every colored block. |

- Comment and bookmark offsets must be `< size`; block ranges are validated.
- Bookmark limit is 8, matching dz6.
- Colors are `0x00RRGGBB`. When omitted, dz6 picks random colors.
- `start` and `end` are inclusive.
- Annotations are document state; they are only durable after `save`.

### Diagnostics

An MCP client only sees stdout, so these tools expose the server's own state and
logs.

| Tool | RO | Parameters | Returns |
| --- | --- | --- | --- |
| `server_info` | ✓ | – | Name, version, pid, uptime, transport, default read-only mode, log level/file, buffered log lines, open files and tool count. |
| `log_level` | – | `level?` | Current filter when omitted; otherwise sets it and reports `changed: true`. |
| `logs_tail` | ✓ | `limit?` | Up to `limit` recent lines (default 100) from a 2000-line ring buffer, newest last. |
| `logs_clear` | – | – | Empties the ring buffer; returns how many lines were dropped. |

`log_level` accepts `trace`, `debug`, `info`, `warn`, `error`, `off`, or an
EnvFilter directive list such as `dz6_mcp=debug,rmcp=info`. Invalid bare values
are rejected; directive lists are validated by `EnvFilter`.

Debugging loop:

```text
Call log_level with {"level": "debug"}, reproduce the problem, then call
logs_tail with {"limit": 50}.
```

## Search syntax

`search` and `search_all` share these parameters:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `needle` | – | Text or hex pattern. Must not be empty. |
| `mode` | `text` | `text` or `hex`. |
| `direction` | `forward` | `forward` or `backward`. |
| `offset` | `search`: cursor (forward) / EOF (backward); `search_all`: `0` / EOF | Start offset. For backward searches it is an **inclusive upper bound**. |
| `next` | `false` | `search` only: skip the current position and return the next/previous occurrence. |
| `ignore_case` | `false` | ASCII case-insensitive matching (text only). |
| `smart_case` | `false` | Disable `ignore_case` when the needle contains an uppercase letter. |
| `wrapscan` | `false` | Wrap around the end/start of the file (`search` only). |
| `max` | `100` | `search_all` only; capped at 10000. |

Hex mode uses dz6's syntax:

| Pattern | Matches |
| --- | --- |
| `4D5A` | literal bytes `4D 5A` |
| `4D5A????0000` | `4D 5A`, any two bytes, `00 00` |
| `4D5A[00-ff]0000` | one byte in `00..=ff` |
| `[41-5a]` | one byte between `41` and `5a` inclusive |

Hex digits must be byte-aligned and even in count. For nibble-level matching,
use `pattern_scan`.

Semantics:

- Searches run against the **effective bytes** (file plus staged edits).
- Forward results are ascending; backward results are descending, but every
  offset is absolute.
- Backward search includes the bound offset (unlike dz6's TUI, which can miss
  the final byte).
- Hex needles that use wildcards compile to a byte regex and report
  non-overlapping matches; plain hex and text needles can overlap.
- `search_all` sets `truncated: true` when it stopped at `max`.
- `search` returns `{found, offset, offset_hex, start_offset, …}`; a miss is not
  an error.

Example:

```json
{
  "path": "/tmp/sample.exe",
  "needle": "4D5A????0000",
  "mode": "hex",
  "direction": "forward",
  "offset": 0
}
```

## Pattern scanning

`pattern_scan` is the signature-oriented companion to `search`. It returns
every match of one or more patterns, can label them, and adds a richer syntax.

```json
{
  "path": "/tmp/sample.bin",
  "patterns": [
    { "name": "elf", "pattern": "7F454C46" },
    { "name": "call-rel32", "pattern": "E8????????" },
    { "name": "pe-exports", "pattern": "50450000{0-8}64" }
  ],
  "offset": 0,
  "length": 65536,
  "max": 200,
  "context": 8
}
```

Parameters:

| Parameter | Default | Meaning |
| --- | --- | --- |
| `path` | – | File to scan. |
| `pattern` | – | Shorthand for one unnamed pattern. Ignored when `patterns` is present. |
| `patterns` | – | Array of `{name?, pattern, mode?, ignore_case?}`. At least one source is required. |
| `mode` | `hex` | Default mode for patterns without their own: `hex` or `text`. |
| `offset` | `0` | First byte of the scan window. |
| `length` | rest of file | Size of the scan window. |
| `max` | `100` | Maximum total matches, capped at 10000. |
| `context` | `0` | Bytes before/after each match, capped at 64. |
| `first_only` | `false` | Return only the earliest match. |
| `include_bytes` | `true` | Include matched bytes as hex. |

Hex syntax (a superset of dz6's):

| Syntax | Meaning | Example |
| --- | --- | --- |
| `4865` / `48 65` | literal bytes; whitespace is ignored | `4D5A` |
| `??` | any single byte | `4D5A??0000` |
| `A?` | high nibble fixed (`0xA0..=0xAF`) | `4?5A` |
| `?A` | low nibble fixed (`0x0A, 0x1A, …, 0xFA`) | `?A` |
| `[00-ff]`, `[41]` | inclusive byte range, or a single byte | `[41-5A]` |
| `{n}`, `{n-m}` | gap of exactly `n`, or `n..=m`, arbitrary bytes | `AA{2-4}BB` |
| `(AA\|BB 43)` | alternation of byte sequences | `(E8\|E9)????????` |
| `VALUE:MASK` | masked match over the whole pattern | `4D5A0000:FFFF0000` |

Masked patterns use the usual bit test: a byte `b` at position `i` matches when
`(b & mask[i]) == (value[i] & mask[i])`. Thus `4D5A0000:FFFF0000` requires
`4D 5A` and ignores the next two bytes, while `05:0F` matches any byte whose
low nibble is `5`.

Semantics and limits:

- Plain hex and text patterns use `memchr` and report **overlapping** matches
  (searching `AA` in `AA AA AA` returns offsets 0, 1 and 2).
- Patterns using any advanced construct compile to a byte regex and report
  **non-overlapping** matches.
- Gaps are limited to 65536 bytes.
- Patterns using advanced constructs are matched against the scan window, so a
  match cannot extend past its bounds.
- `first_only` returns the earliest match across all patterns.
- Results are sorted by offset and then pattern order, and include `pattern`,
  `name`, `mode`, `offset`, `offset_hex`, `length`, optional `bytes`, and
  optional `context_offset`, `context_before`, `context_after`.
- The response includes the compiled pattern list, `count` and `truncated`.
- Scanning uses the effective bytes, so staged edits are visible.
- Invalid patterns return an error naming the pattern and the problem.

Example response fragment:

```json
{
  "count": 1,
  "truncated": false,
  "matches": [
    {
      "pattern": "7F454C46",
      "name": "elf",
      "mode": "hex",
      "offset": 0,
      "offset_hex": "0x0",
      "length": 4,
      "bytes": "7F 45 4C 46",
      "context_offset": 0,
      "context_before": "",
      "context_after": "02 01 01 00 00 00 00 00"
    }
  ]
}
```

## PE/ELF reference

### Which tool should I use?

| Question | Tool |
| --- | --- |
| Is this a PE/ELF, and what does the header say? | `headers` |
| Where are the sections/segments, and which are executable or packed? | `sections` |
| What functions/imports/exports exist? | `symbols` |
| What file offset corresponds to this address? | `address_translate` |
| What bytes are at this address? | `read_at_address` |
| What PDB, TLS callbacks, certificates, resources or overlay does this PE have? | `pe_info` |
| What libraries, RPATH, build-id or dynamic tags does this ELF have? | `elf_info` |

### Address translation rules

**PE**

```text
VA  = image_base + RVA
RVA = VA - image_base

headers region:  RVA < SizeOfHeaders            → offset = RVA
section region:  RVA in [VA, VA + span)         → offset = PointerToRawData + (RVA - VA)
                 span = max(VirtualSize, SizeOfRawData)
                 the result must fall inside SizeOfRawData
```

The reverse maps header offsets directly and otherwise uses
`PointerToRawData..PointerToRawData + SizeOfRawData`. Inputs below `image_base`
are rejected for VA lookups; use `kind: "rva"` when your disassembler prints
RVAs.

**ELF**

```text
VA → offset:  first PT_LOAD where p_vaddr <= va < p_vaddr + p_filesz
              offset = p_offset + (va - p_vaddr)
              fallback: section where sh_addr <= va < sh_addr + sh_size

offset → VA:  first PT_LOAD where p_offset <= off < p_offset + p_filesz
              va = p_vaddr + (off - p_offset)
              fallback: section where sh_offset <= off < sh_offset + sh_size
```

`p_filesz` (not `p_memsz`) is used for file offsets because `.bss` has no file
backing. Section ownership uses `p_memsz` so `.bss` is still attributed to its
segment.

### Coverage and limitations

- **Formats**: PE (PE32/PE32+) and ELF (ELF32/ELF64, little or big endian).
  Mach-O is detected by dz6's file-type sniffing but not parsed by these tools;
  `headers` returns `parsed: false` for it.
- **No disassembly, xrefs or decompilation.** dz6-mcp is a byte-level editor
  and parser. Pair it with a disassembler or a REA provider for that.
- **PE symbols**: `symbols` exposes exports/imports, not the COFF symbol table.
- **PE resources**: summary counts plus version/manifest presence, not a full
  resource tree walk.
- **Certificates**: presence and metadata only; PKCS#7/Authenticode is not
  validated.
- **ELF symbols**: `.symtab` is preferred when present, otherwise `.dynsym`.
  Symbol version names are not resolved; `elf_info` reports version
  definition/requirement counts.
- **ELF notes**: read from note segments first, then note sections.
- **ELF dynamic tags**: exposed as raw `{tag, value}` pairs (first 256).
- **Structural tools read the on-disk mapping**, so staged header edits are not
  reflected until `save` (or a reopen).
- **Malformed/packed files**: goblin may reject a file that dz6's TUI still
  displays as raw bytes. In that case use `read_bytes`, `search` and
  `pattern_scan`, which do not require a valid header.

## Workflows

### Triage an unknown file

```text
file_info    {"path": "/tmp/sample.bin"}
analyze      {"path": "/tmp/sample.bin"}
strings      {"path": "/tmp/sample.bin", "min_length": 6, "max": 200}
pattern_scan {"path": "/tmp/sample.bin", "patterns": [
               {"name": "mz",  "pattern": "4D5A"},
               {"name": "elf", "pattern": "7F454C46"},
               {"name": "zip", "pattern": "504B0304"},
               {"name": "png", "pattern": "89504E470D0A1A0A"}
             ]}
read_bytes   {"path": "/tmp/sample.bin", "offset": 0, "length": 128}
```

High entropy plus few strings suggests compression or encryption; use
`sections`/`pe_info` overlay information when the container is PE.

### PE triage

```text
open_file          {"path": "/tmp/sample.exe"}
file_info          {"path": "/tmp/sample.exe"}
headers            {"path": "/tmp/sample.exe"}
sections           {"path": "/tmp/sample.exe"}
pe_info            {"path": "/tmp/sample.exe"}
symbols            {"path": "/tmp/sample.exe", "kind": "import", "name_regex": "^Win"}
address_translate  {"path": "/tmp/sample.exe", "address": "0x140001000"}
read_at_address    {"path": "/tmp/sample.exe", "address": "0x140001000", "length": 64}
```

Look at `debug.pdb.path` for build paths, `tls.callbacks` for TLS callbacks,
`certificates` for signing, `resources.manifest` for UAC information, and
`overlay` for appended data. `sections` entropy highlights packed or encrypted
sections.

### ELF triage

```text
elf_info           {"path": "/bin/ls"}
sections           {"path": "/bin/ls"}
symbols            {"path": "/bin/ls", "kind": "function", "name_regex": "main|init"}
address_translate  {"path": "/bin/ls", "address": "0x2000"}
read_at_address    {"path": "/bin/ls", "address": "0x2000", "length": 32}
```

`elf_info` gives the interpreter, NEEDED libraries, RPATH/RUNPATH and build-id
(useful for matching debug symbols); `symbols` with `dynamic_only` reflects
what the dynamic linker actually sees. Addresses in these examples are
illustrative, take real ones from `headers`/`sections` or your disassembler.

### Signature scanning

Find every indirect call/jump and every `call rel32`, with context:

```json
{
  "path": "/tmp/sample.exe",
  "patterns": [
    { "name": "call-rel32", "pattern": "E8????????" },
    { "name": "jmp-rel32", "pattern": "E9????????" },
    { "name": "indirect", "pattern": "(FF15|FF25)" },
    { "name": "int3-pad", "pattern": "CC{4-16}" }
  ],
  "max": 500,
  "context": 16
}
```

Find a masked value, such as a PE `MZ` signature with the next two bytes
ignored:

```json
{ "path": "/tmp/sample.bin", "pattern": "4D5A0000:FFFF0000", "max": 50 }
```

The `VALUE:MASK` form has no wildcard token on purpose: a zero mask bit ignores
that byte, so `4D5A0000:FFFF0000` matches `4D 5A` followed by any two bytes.

### Patch and verify

```text
write_bytes {"path": "/tmp/sample.exe", "offset": 4096, "data": "90 90 90"}
read_bytes  {"path": "/tmp/sample.exe", "offset": 4096, "length": 16}
save        {"path": "/tmp/sample.exe"}
```

`read_bytes` sees the staged patch immediately. If the change is wrong, call
`undo` before `save`. `save` also writes the `<file>.dz6` sidecar.

For a NOP fill:

```text
fill {"path": "/tmp/sample.exe", "offset": 4096, "length": 12, "kind": "nop"}
```

### Ghidra-free reverse engineering with REA

`dz6-mcp` and [REA](https://github.com/mentebinaria/rea) are complementary:

- **REA** provides the analysis layer: Rizin, GNU objdump, GDB and Frida
  (`execute_rizin_command`, `inspect_with_objdump`, debuggers), plus optional
  deep providers for decompilation.
- **dz6-mcp** provides byte-level ground truth: exact bytes, patterns, PE/ELF
  structures, VA↔offset translation and staging/saving patches.

A Ghidra-free loop:

```text
REA:  execute_rizin_command {"path": "/tmp/sample", "command": "aaa;afl"}          # functions
REA:  execute_rizin_command {"path": "/tmp/sample", "command": "aaa;pdf @ sym.main"} # disassembly
dz6:  address_translate  {"path": "/tmp/sample", "address": "0x401234"}
dz6:  read_at_address    {"path": "/tmp/sample", "address": "0x401234", "length": 64}
dz6:  pattern_scan       {"path": "/tmp/sample", "pattern": "E8????????", "max": 100}
dz6:  write_bytes        {"path": "/tmp/sample", "offset": 4660, "data": "90 90"}
dz6:  save               {"path": "/tmp/sample"}
REA:  inspect_with_objdump {"path": "/tmp/sample", "operation": "file_headers"}
```

REA records `artifact_sha256_after` and `artifact_changed`, so re-running an
REA inspection after `save` confirms the patch on disk. Rizin's one-shot
`execute_rizin_command` needs chained commands (`aaa;afl`, `aaa;pdf @ sym.main`,
`axt @ 0x...`) because each call starts a fresh process. Without a deep
provider, use REA's Rizin/objdump/GDB tools for inspection and disassembly, and
dz6-mcp for exact bytes, structures and patching.

### Annotate while you work

```text
comment_set  {"path": "/tmp/sample.exe", "offset": 4096, "comment": "entry thunk"}
bookmark_add {"path": "/tmp/sample.exe", "offset": 4096}
block_add    {"path": "/tmp/sample.exe", "start": 4096, "end": 4127, "bg_color": 3368601}
comments_list {"path": "/tmp/sample.exe"}
save         {"path": "/tmp/sample.exe"}
```

### Scripted sessions

Any JSON-RPC client can drive the server. Keep one process per session so the
document cache, staged edits and annotations persist; use `close_file` to reset
a document and `--readonly` for untrusted inputs.

## Architecture

| Path | Responsibility |
| --- | --- |
| `src/main.rs` | CLI parsing, logging initialization, stdio transport. |
| `src/server.rs` | `Dz6Server`, router composition, tool-call logging, MCP instructions. |
| `src/state.rs` | `ServerState` and `Document`: canonical paths, lazy open, read-only mode, close. |
| `src/ops.rs` | TUI-free operations: reads, effective ranges, search, edits, save, truncate, header serialization, strings. |
| `src/pattern.rs` | Signature engine: hex-pattern translator and scanner. |
| `src/binary.rs` | Deep PE/ELF layout, symbols, address translation, PE/ELF metadata. |
| `src/tools/*.rs` | MCP surface, one router per group. |
| `src/logging.rs` | Tracing subscriber, reloadable `EnvFilter`, tee writer, 2000-line ring buffer. |

Data flow for a read: JSON-RPC → `rmcp` → tool method → `ServerState::open_doc`
→ `ops` / `binary` → JSON.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| "server not connected" / no tools | `command` points at a directory, or the binary was moved/rebuilt elsewhere | Use the absolute path to the executable (`…/target/release/dz6-mcp`). Verify with `codex mcp get dz6`, `claude mcp get dz6`, or the client's MCP panel. |
| New tools missing after upgrade | The client cached the old `tools/list` | Reconnect/restart the session. `server_info` should report `tools: 39`. |
| Server exits immediately | Bad CLI flag, unwritable `--log-file`, or a dz6 library mismatch | Run the binary by hand with `-v` and read stderr. |
| No per-call logs | Default level is `warn` | Start with `-v`, or call `log_level {"level": "info"}`. |
| `save` fails with permission denied | File opened read-only or not writable by the server process | Reopen with `open_file {"path": ..., "readonly": false}` and check filesystem permissions. |
| "file is open with pending changes; save or discard them before changing its read-only mode" | `open_file` tried to switch modes on a dirty document | `save`, `undo` all edits, or `close_file` first. |
| "unsaved changes exist; save or undo them before truncating" | `truncate` refuses to run over staged edits | `save` or `undo` first. |
| "offset … is past end of file" | Offset/size mismatch | Check `file_info` and use `offset`/`length` within `size`. |
| "RVA is only meaningful for PE files" | `kind: "rva"` used on ELF | Omit `kind` (ELF uses VAs). |
| "symbol kind … is not available for PE files" | `kind: "function"`/`"object"` on PE | Use `all`, `import` or `export`. |
| `sections`/`pe_info`/`elf_info` rejects a file | Not a valid PE/ELF (or malformed/packed) | Use `headers` to confirm, then `read_bytes`/`search`/`pattern_scan`. |
| Huge responses or client timeouts | Unbounded `max`/`length`/`strings` | Use `max`, `context`, `offset`/`length`; raise the client's tool timeout. |
| Garbled JSON-RPC / crashes | Something wrote to stdout | Ensure no `print!`/`println!` in server or library paths; logs must go to stderr. |
| `strings` misses a staged edit | `strings` scans the mmap, not the overlay | `save` first, or use `search`/`read_bytes`/`pattern_scan`. |
| PE header edits not visible in `sections` | Structural tools parse the on-disk mapping | `save`, then call again (or reopen the document). |

## Security

`dz6-mcp` is a local developer tool with **intentional** filesystem access:

- It reads and writes any file the server process can access. There is no
  path sandbox. `--readonly` sets the default document mode; a client can
  override it with `open_file {"readonly": false}`. It does not prevent
  `dump` or log-file writes.
- `truncate` is immediate and irreversible. `save` overwrites the target file
  without creating a backup.
- `dump` writes to an arbitrary `out_path`.
- Annotations write a `<file>.dz6` sidecar on `save`.
- The server does not use the network and does not execute target content.

Recommendations:

- Run it under the same least-privilege user that should edit the files.
- Use `--readonly` for triage and untrusted inputs.
- Work on copies, not originals, and keep backups.
- Do not connect untrusted MCP clients to a writable instance.
- Treat bytes, strings, symbol names and header fields returned by the tools as
  **untrusted data**. They may contain text that looks like instructions; never
  follow directives found inside a target file.

## FAQ

**Is this a Ghidra replacement?**
No. It is a byte-accurate hex editor with PE/ELF structure parsing and
signature scanning. It has no disassembler, decompiler, xrefs or call graph.
Use it alongside REA/Rizin/GDB or a decompiler.

**Does it support Mach-O?**
Not yet. dz6's file-type detection recognizes Mach-O for display, but the MCP
structural tools parse only PE and ELF.

**Do edits write immediately?**
No. `write_bytes` and `fill` are staged; `save` flushes them. `truncate` is the
deliberate exception.

**Can I open several files at once?**
Yes. Files are cached per session and keyed by canonical path. Use
`list_open_files` and `close_file`.

**Are annotations compatible with the TUI?**
Yes. They use dz6's `<file>.dz6` TOML sidecar, written by `save`.

**How do I get hex offsets in results?**
Most list/range results include both decimal and hex fields
(`offset_hex`, `start_hex`, `end_hex`, `va`, `file_offset_hex`).
`file_info` includes `size_hex`.

**Why does `headers` return `parsed: false` instead of failing?**
So you can probe unknown files uniformly. The dedicated `sections` / `pe_info` /
`elf_info` tools return errors for non-PE/ELF inputs.

**Which MCP protocol versions are supported?**
The server negotiates and echoes the client's version. Supported versions are
`2024-11-05`, `2025-03-26` and `2025-06-18`.

**How many tools are there?**
39. `server_info` reports the live count.

## License

GPL-3.0-or-later, matching dz6. See [LICENSE](LICENSE).
