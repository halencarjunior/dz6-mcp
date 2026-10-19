# Reverse engineering the assembly demo with dz6-mcp

**English** | [Português (Brasil)](assembly-demo.pt-BR.md) | [Main README](../README.md)

This lab takes you from connecting an MCP client to finding and patching a one-byte access flag. You can inspect the same file in the dz6 terminal editor and use a disassembler to explain its instructions. The included verifier exercises all 39 MCP tools using disposable copies.

## What is included

| File | Purpose |
| --- | --- |
| [`demo.s`](../examples/assembly/demo.s) | Commented x86-64 assembly in GNU assembler Intel syntax. |
| [`demo.elf`](../examples/assembly/bin/demo.elf) | Linux executable, no libc or dynamic dependencies. Prints `Access denied!` initially. |
| [`demo.exe`](../examples/assembly/bin/demo.exe) | PE32+ inspection fixture with exported symbols. Not intended for execution on Windows. |
| [`manifest.json`](../examples/assembly/bin/manifest.json) | File offsets, virtual addresses and sections for named landmarks in both files. |
| [`build.py`](../examples/assembly/build.py) | Rebuilds both fixtures and their manifest with GNU binutils. |
| [`verify.py`](../examples/assembly/verify.py) | Drives the real stdio MCP server, checks results and verifies coverage of every advertised tool. |

The ELF uses only Linux `write` and `exit` syscalls. It reads `demo_gate`: zero selects the denial message, while a nonzero value selects the success message. It does not ask for a password. The PE shares the data layout and gate routine but omits the Linux syscalls.

The fixtures contain UTF-8, Latin-1, UTF-16LE and UTF-16BE strings; signed and unsigned integers; named signatures; a 256-byte ramp; a zero-filled region; a NOP workspace; and `.bss` storage without file-backed bytes.

These are small teaching fixtures, not examples of every optional executable directory. The PE has exports but no actual imported APIs, PDB, TLS callbacks, resources or certificate. The static ELF has no interpreter, NEEDED libraries or dynamic symbol table. The corresponding metadata is absent or empty. Use the main [tool reference](../README.md#tool-reference) for the full capabilities.

## 1. Prepare the tools and working copies

First follow the [build requirements](../README.md#requirements) to prepare the patched dz6 library and compile the MCP server:

```sh
cargo build --locked
```

The prebuilt fixtures can be inspected immediately. Rebuilding requires Python 3 and GNU `as`, `ld`, `nm` and `objdump`. The linker must support `elf_x86_64` and `i386pep`, as Ubuntu's GNU binutils does:

```sh
ld -V
python3 examples/assembly/build.py
```

Rebuilding updates `manifest.json`; offsets may change with another linker version. The numbers below refer to the included binaries. Check the manifest or discover offsets through MCP before patching a rebuilt file.

From the repository root, create working copies:

```sh
mkdir -p /tmp/dz6-mcp-demo
cp examples/assembly/bin/demo.elf /tmp/dz6-mcp-demo/demo.elf
cp examples/assembly/bin/demo.exe /tmp/dz6-mcp-demo/demo.exe
chmod u+x /tmp/dz6-mcp-demo/demo.elf
```

These commands are for Linux. Native execution requires Linux x86-64. Inspection through the MCP server does not execute either fixture. Keep the files in `examples/assembly/bin` unchanged while doing the lab. Restarting the exercise means closing its documents, copying the fixtures again and removing any old working-copy `.dz6` sidecars if you want to reset annotations.

On Linux x86-64, establish the original behavior before opening the file writable:

```sh
/tmp/dz6-mcp-demo/demo.elf
# Access denied!
```

## 2. Connect an MCP client

Use the appropriate [client configuration](../README.md#harness-configuration). For example, replace the command below with the absolute path to your build:

```json
{
  "mcpServers": {
    "dz6": {
      "command": "/absolute/path/to/dz6-mcp/target/debug/dz6-mcp",
      "args": ["--readonly", "-v"]
    }
  }
}
```

Reconnect the client, then ask:

> Use the dz6 MCP tools to inspect `/tmp/dz6-mcp-demo/demo.elf`. Start with server_info, file_info, headers, sections and symbols. Find check_gate and demo_gate, explain the difference between a virtual address and a file offset, and show the bytes at both locations. Keep the file read-only until I ask to patch it.

`--readonly` is the default opening mode, not an enforced sandbox. A later `open_file` call with `readonly: false` enables the editing part of this lab.

The blocks below show **tool names and JSON arguments**, not shell commands. Ask your MCP client to make these calls. It may display names with a prefix such as `mcp__dz6__`.

## 3. Identify the format and locate the gate

```text
server_info     {}
open_file       {"path":"/tmp/dz6-mcp-demo/demo.elf","readonly":true}
list_open_files {}
file_info       {"path":"/tmp/dz6-mcp-demo/demo.elf"}
headers         {"path":"/tmp/dz6-mcp-demo/demo.elf"}
sections        {"path":"/tmp/dz6-mcp-demo/demo.elf"}
elf_info        {"path":"/tmp/dz6-mcp-demo/demo.elf"}
symbols         {"path":"/tmp/dz6-mcp-demo/demo.elf","name_regex":"^(_start|check_gate|demo_gate)$"}
```

Expected findings: ELF64, x86-64, an entry point in `.text`, readable constants in `.rodata`, a writable flag in `.data`, and a `.bss` region. `server_info` reports 39 tools. `elf_info` reports the GNU build-id; no dynamic interpreter is needed.

Landmarks in the included ELF:

| Symbol | File offset (decimal) | VA | Meaning |
| --- | --- | --- | --- |
| `_start` | 4096 | `0x401000` | Entry point. |
| `check_gate` | 4152 | `0x401038` | Reads the gate byte into EAX and returns. |
| `patch_pad` | 4160 | `0x401040` | 16 NOP bytes outside the executed path. |
| `demo_magic` | 8192 | `0x402000` | `DZ6DEMO` followed by NUL. |
| `number_le` | 8200 | `0x402008` | `0x12345678`. |
| `signed_value` | 8204 | `0x40200c` | Signed 32-bit `-42`. |
| `signature_lab` | 8351 | `0x40209f` | Known bytes for pattern searches. |
| `entropy_ramp` | 8363 | `0x4020ab` | Every byte value from 0 to 255. |
| `zero_pad` | 8619 | `0x4021ab` | 256 zero bytes. |
| `demo_gate` | 8875 | `0x4032ab` | Initially `00`; patch to `01`. |

Confirm the mapping in both directions:

```text
address_translate {"path":"/tmp/dz6-mcp-demo/demo.elf","address":"0x4032ab"}
address_translate {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875}
read_at_address   {"path":"/tmp/dz6-mcp-demo/demo.elf","address":"0x401038","length":8}
read_bytes        {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"length":1}
```

The gate maps to offset 8875, and its byte is `00`. `scratch_buffer` lives in `.bss`, so it has a virtual address but no backing bytes to read from the file.

## 4. Explain the instructions with a disassembler

The MCP server provides exact bytes and structures; use GNU objdump for instructions:

```sh
objdump -d -Mintel /tmp/dz6-mcp-demo/demo.elf
```

At `_start`, follow `call check_gate`, `test eax,eax`, and the conditional branch. At `check_gate`, identify the RIP-relative `movzx` that reads `demo_gate`, followed by `ret`. The returned value selects one of the two output strings. Changing the data byte is enough to change the result without replacing an instruction.

You can also ask an assistant with REA available to inspect the same working copy using Rizin or objdump, then use dz6-mcp to confirm offsets and bytes. REA is optional; no external analysis service is required for this lab.

## 5. Read numbers and strings

```text
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8200,"size":4,"endian":"little"}
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8200,"size":4,"endian":"big"}
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8204,"size":4,"signed":true}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8208,"encoding":"utf8"}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8234,"encoding":"latin1"}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8238,"encoding":"utf16le"}
read_string {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8246,"encoding":"utf16be"}
strings     {"path":"/tmp/dz6-mcp-demo/demo.elf","regex":"DEMO_TAG|Access","max":20}
```

Little endian produces `305419896`; reading the same bytes as big endian produces `2018915346`. The signed value is `-42`. The first string is `Hello, dz6! Olá, Brasil!`; the three other encodings decode to `Olá`. `strings` finds printable ASCII sequences, so use `read_string` for these non-ASCII encoding exercises.

## 6. Search and scan signatures

```text
goto       {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8192}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DZ6DEMO"}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"findme","ignore_case":true,"offset":0}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DEMO_TAG:","direction":"backward"}
search_all {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DEMO_TAG:","max":10}
search     {"path":"/tmp/dz6-mcp-demo/demo.elf","needle":"DEAD????","mode":"hex","offset":8351}
```

There are three `DEMO_TAG:` strings. `goto` sets the default forward-search cursor. Backward searches return absolute offsets in descending order. Try `next: true` to skip the current match and `wrapscan: true` to wrap a `search` around the end of the file.

Call `pattern_scan` with this object:

```json
{
  "path": "/tmp/dz6-mcp-demo/demo.elf",
  "offset": 8192,
  "length": 171,
  "context": 4,
  "patterns": [
    {"name":"literal","pattern":"DEADBEEF"},
    {"name":"nibble","pattern":"A?5A"},
    {"name":"range","pattern":"[A0-AF]5A"},
    {"name":"gap","pattern":"5A{2}BB"},
    {"name":"alternative","pattern":"(DEAD|BEEF)"},
    {"name":"mask","pattern":"A050:F0F0"},
    {"name":"overlap","pattern":"AAAA"},
    {"name":"text","pattern":"DEMO_TAG:","mode":"text"}
  ]
}
```

Every named pattern matches. `AAAA` has two overlapping matches in the three `AA` bytes. The mask checks selected bits, and the gap consumes two arbitrary bytes. Repeat with `first_only: true` or a small `max` to examine the result limits.

## 7. Compare entropy and extract data

```text
analyze {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8363,"length":256}
analyze {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8619,"length":256}
dump    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8192,"length":8,"out_path":"/tmp/dz6-mcp-demo/extracted.bin"}
```

The byte ramp has entropy 8 bits/byte and 256 distinct values. The zero region has entropy 0. High entropy alone does not prove encryption; this ramp is entirely predictable. The extracted file contains `DZ6DEMO` and NUL. `dump` writes its destination even when the source document is read-only.

## 8. Annotate the discoveries

Enable writes for the working copy before saving annotations:

```text
open_file     {"path":"/tmp/dz6-mcp-demo/demo.elf","readonly":false}
comment_set   {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"comment":"Access flag: 0=deny, 1=grant"}
comments_list {"path":"/tmp/dz6-mcp-demo/demo.elf"}
bookmark_add  {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875}
bookmarks_list {"path":"/tmp/dz6-mcp-demo/demo.elf"}
block_add     {"path":"/tmp/dz6-mcp-demo/demo.elf","start":8351,"end":8362,"bg_color":3368601}
blocks_list   {"path":"/tmp/dz6-mcp-demo/demo.elf"}
save          {"path":"/tmp/dz6-mcp-demo/demo.elf"}
```

Confirm `database_saved: true`. Annotations go into `/tmp/dz6-mcp-demo/demo.elf.dz6`, shared with the dz6 TUI. If database saving is disabled in your dz6 configuration, enable it before continuing.

## 9. Rehearse undo, then patch the gate

First fill four bytes of the unused NOP workspace, then undo those four byte edits:

```text
fill       {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":4160,"length":4,"kind":"zero"}
read_bytes {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":4160,"length":4}
undo       {"path":"/tmp/dz6-mcp-demo/demo.elf","steps":4}
read_bytes {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":4160,"length":4}
```

The bytes return to `90 90 90 90`. `steps` counts byte edits, not tool calls.

Now patch the gate:

```text
write_bytes {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"data":"01"}
read_int    {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"size":1}
file_info   {"path":"/tmp/dz6-mcp-demo/demo.elf"}
save        {"path":"/tmp/dz6-mcp-demo/demo.elf"}
close_file  {"path":"/tmp/dz6-mcp-demo/demo.elf"}
```

Before `save`, MCP reads see `1`, but the file on disk still contains `0`. After saving, `pending_changes` is zero. Close the writable document before executing, or Linux can return `Text file busy`:

```sh
/tmp/dz6-mcp-demo/demo.elf
# Access granted
```

Ask your assistant:

> Explain why this one-byte data patch changes the branch outcome. Show the saved flag, the check_gate instructions and the output strings. Distinguish evidence from the file from your interpretation of the code.

## 10. Open the same file in dz6

Build the terminal editor from the patched sibling checkout if needed:

```sh
cargo build --manifest-path ../dz6/Cargo.toml --bin dz6
../dz6/target/debug/dz6 -r /tmp/dz6-mcp-demo/demo.elf
```

If your Cargo setup uses a shared target directory, adjust the executable path accordingly. In dz6:

- Type `:8875t` and Enter to jump to decimal offset 8875, or `:22ab` for hexadecimal `0x22ab`.
- Inspect the `01` byte and the saved comment at the gate.
- Press `Tab` to cycle between Hex, Text and Headers.
- Use `/` to search for `Access`; `Tab` in search mode switches between text and hexadecimal.
- Type `:q` to quit.

The correct decimal jump command is `:8875t`; offsets in dz6 default to hexadecimal, while MCP numeric offsets are decimal. Keep TUI inspection read-only and reopen the MCP document after external edits to refresh cached state.

## 11. Inspect the PE companion

```text
open_file         {"path":"/tmp/dz6-mcp-demo/demo.exe","readonly":true}
headers           {"path":"/tmp/dz6-mcp-demo/demo.exe"}
sections          {"path":"/tmp/dz6-mcp-demo/demo.exe"}
pe_info           {"path":"/tmp/dz6-mcp-demo/demo.exe"}
symbols           {"path":"/tmp/dz6-mcp-demo/demo.exe","kind":"export","name_regex":"check_gate|demo_gate"}
symbols           {"path":"/tmp/dz6-mcp-demo/demo.exe","kind":"import"}
address_translate {"path":"/tmp/dz6-mcp-demo/demo.exe","address":"0x140001000"}
address_translate {"path":"/tmp/dz6-mcp-demo/demo.exe","address":"0x1000","kind":"rva"}
read_at_address   {"path":"/tmp/dz6-mcp-demo/demo.exe","address":"0x140001000","length":16}
```

For the included PE, both address translations resolve to offset 1024: VA equals image base `0x140000000` plus RVA `0x1000`. Use PE exports to find labels; PE `symbols` does not expose the COFF symbol table. The fixture has no actual API imports. `elf_info` on this file, or `pe_info` on the ELF, should return a format error.

## 12. Practice cleanup and truncation

Reopen the ELF writable to remove annotations if desired. An empty comment removes that comment:

```text
open_file       {"path":"/tmp/dz6-mcp-demo/demo.elf","readonly":false}
comment_set     {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875,"comment":""}
bookmark_remove {"path":"/tmp/dz6-mcp-demo/demo.elf","offset":8875}
bookmark_clear  {"path":"/tmp/dz6-mcp-demo/demo.elf"}
block_clear     {"path":"/tmp/dz6-mcp-demo/demo.elf"}
save            {"path":"/tmp/dz6-mcp-demo/demo.elf"}
close_file      {"path":"/tmp/dz6-mcp-demo/demo.elf"}
close_file      {"path":"/tmp/dz6-mcp-demo/demo.exe"}
```

Use only the extracted raw file for truncation:

```text
open_file  {"path":"/tmp/dz6-mcp-demo/extracted.bin","readonly":false}
truncate   {"path":"/tmp/dz6-mcp-demo/extracted.bin","offset":5,"mode":"after"}
truncate   {"path":"/tmp/dz6-mcp-demo/extracted.bin","offset":3,"mode":"before"}
read_bytes {"path":"/tmp/dz6-mcp-demo/extracted.bin","offset":0,"length":3}
close_file {"path":"/tmp/dz6-mcp-demo/extracted.bin"}
```

The sizes become 6 and then 3 bytes, leaving `DEM` (`44 45 4D`). These changes are immediate and cannot be undone. Do not truncate an executing or externally mapped executable.

## 13. Inspect logs and run the complete verification

```text
log_level  {"level":"debug"}
server_info {}
logs_tail  {"limit":20}
logs_clear {}
log_level  {"level":"warn"}
```

Run the automated counterpart from the repository root:

```sh
python3 examples/assembly/verify.py --server target/debug/dz6-mcp
```

It creates a temporary directory, calls every tool advertised by `tools/list`, checks representative results, verifies annotation persistence after reopening, and removes its working files when done. On Linux x86-64, it also executes the ELF before and after patching. Use `--skip-execution` for inspection-only verification. The PE is never executed.

Expected output:

```text
PASS: all 39 MCP tools; ELF/PE inspection, encodings, signatures, edits, sidecar and truncation
PASS: saved gate patch changes Linux output
```

The CI workflow rebuilds the fixtures and runs this verification against a freshly built MCP server. You can repeat the manual steps independently; the verifier does not depend on your `/tmp/dz6-mcp-demo` session.
