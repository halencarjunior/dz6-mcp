#!/usr/bin/env python3
"""Exercise all advertised MCP tools against disposable assembly fixtures."""
import argparse
import json
from pathlib import Path
import platform
import queue
import shutil
import subprocess
import tempfile
import threading

HERE = Path(__file__).resolve().parent


class Client:
    def __init__(self, executable, stderr):
        self.process = subprocess.Popen(
            [str(executable), "--readonly"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=stderr, text=True, bufsize=1,
        )
        self.responses = queue.Queue()
        self.sequence = 0
        self.used = set()
        threading.Thread(target=self.read, daemon=True).start()
        self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "dz6-assembly-demo", "version": "1"},
        })
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.available = {tool["name"] for tool in self.request("tools/list", {})["tools"]}

    def read(self):
        for line in self.process.stdout:
            self.responses.put(line)
        self.responses.put(None)

    def send(self, message):
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        self.send({"jsonrpc": "2.0", "id": self.sequence, "method": method, "params": params})
        while True:
            line = self.responses.get(timeout=15)
            assert line is not None, "Server exited before responding"
            response = json.loads(line)
            if response.get("id") == self.sequence:
                assert "error" not in response, response
                return response["result"]

    def tool(self, name, *, error=False, **arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        assert bool(result.get("isError")) == error, (name, result)
        self.used.add(name)
        value = result.get("structuredContent")
        if value is None:
            value = json.loads(result["content"][0]["text"])
        return value

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()


def exercise(client, directory, execute):
    manifest = json.loads((HERE / "bin/manifest.json").read_text())
    elf = directory / "demo.elf"
    pe = directory / "demo.exe"
    for path in (elf, pe):
        shutil.copy2(HERE / "bin" / path.name, path)
    symbols = manifest["elf"]["symbols"]
    offset = lambda name: symbols[name]["offset"]
    path = str(elf)
    call = client.tool
    if execute:
        assert subprocess.check_output([path], text=True, timeout=5) == "Access denied!\n"
    assert call("server_info")["tools"] == 39
    call("log_level", level="debug")
    call("open_file", path=path, readonly=True)
    assert call("file_info", path=path)["readonly"]
    assert call("list_open_files")["count"] == 1
    assert call("headers", path=path)["parsed"]
    call("sections", path=path)
    call("elf_info", path=path)
    call("pe_info", path=path, error=True)
    found = call("symbols", path=path, name_regex="^check_gate$", kind="function")
    assert found["count"] == 1, found
    translated = call("address_translate", path=path, address=symbols["demo_magic"]["va"])
    assert translated["file_offset"] == offset("demo_magic"), translated
    call("address_translate", path=path, offset=offset("demo_magic"))
    call("read_at_address", path=path, address=symbols["demo_magic"]["va"], length=8)
    assert call("read_bytes", path=path, offset=0, length=4)["hex"] == "7F 45 4C 46"
    assert call("read_int", path=path, offset=offset("number_le"), size=4)["decimal"] == "305419896"
    assert call("read_int", path=path, offset=offset("signed_value"), size=4, signed=True)["decimal"] == "-42"
    for name, encoding in (("greeting_utf8", "utf8"), ("greeting_latin1", "latin1"),
                           ("greeting_utf16le", "utf16le"), ("greeting_utf16be", "utf16be")):
        decoded = call("read_string", path=path, offset=offset(name), encoding=encoding)
        assert "Olá" in decoded["text"], decoded
    call("goto", path=path, offset=offset("demo_magic"))
    assert call("search", path=path, needle="DZ6DEMO")["offset"] == offset("demo_magic")
    assert call("search_all", path=path, needle="DEMO_TAG:")["count"] == 3
    call("search", path=path, needle="dead????", mode="hex", offset=offset("signature_lab"))
    call("search", path=path, needle="findme", ignore_case=True, offset=0)
    call("search", path=path, needle="DEMO_TAG:", direction="backward")
    patterns = [
        {"name": "literal", "pattern": "DEADBEEF"},
        {"name": "nibble", "pattern": "A?5A"},
        {"name": "range", "pattern": "[A0-AF]5A"},
        {"name": "gap", "pattern": "5A{2}BB"},
        {"name": "alternative", "pattern": "(DEAD|BEEF)"},
        {"name": "mask", "pattern": "A050:F0F0"},
        {"name": "overlap", "pattern": "AAAA"},
        {"name": "text", "pattern": "DEMO_TAG:", "mode": "text"},
    ]
    scan = call("pattern_scan", path=path, patterns=patterns, offset=offset("demo_magic"),
                length=offset("entropy_ramp") - offset("demo_magic"), context=4)
    assert {m["name"] for m in scan["matches"]} == {p["name"] for p in patterns}, scan
    call("strings", path=path, regex="DEMO_TAG", max=20)
    assert call("analyze", path=path, offset=offset("entropy_ramp"), length=256)["entropy"] == 8.0
    assert call("analyze", path=path, offset=offset("zero_pad"), length=256)["entropy"] == 0.0
    dump = directory / "extracted.bin"
    call("dump", path=path, out_path=str(dump), offset=offset("demo_magic"), length=8)
    assert dump.read_bytes() == b"DZ6DEMO\0"
    call("write_bytes", path=path, offset=offset("demo_gate"), data="01", error=True)
    call("open_file", path=path, readonly=False)
    call("fill", path=path, offset=offset("patch_pad"), length=4, kind="zero")
    call("undo", path=path, steps=4)
    assert call("read_bytes", path=path, offset=offset("patch_pad"), length=4)["hex"] == "90 90 90 90"
    call("comment_set", path=path, offset=offset("demo_gate"), comment="Access flag: 0=deny, 1=grant")
    call("comments_list", path=path)
    call("bookmark_add", path=path, offset=offset("demo_gate"))
    call("bookmarks_list", path=path)
    call("bookmark_remove", path=path, offset=offset("demo_gate"))
    call("bookmark_add", path=path, offset=offset("demo_gate"))
    call("bookmark_clear", path=path)
    call("block_add", path=path, start=offset("signature_lab"), end=offset("signature_lab")+11,
         bg_color=3368601)
    call("blocks_list", path=path)
    call("block_clear", path=path)
    call("write_bytes", path=path, offset=offset("demo_gate"), data="01")
    assert elf.read_bytes()[offset("demo_gate")] == 0
    assert call("read_int", path=path, offset=offset("demo_gate"), size=1)["decimal"] == "1"
    saved = call("save", path=path)
    assert saved["database_saved"], saved
    assert Path(path + ".dz6").exists()
    assert elf.read_bytes()[offset("demo_gate")] == 1
    call("close_file", path=path)
    if execute:
        assert subprocess.check_output([path], text=True, timeout=5) == "Access granted\n"
    call("open_file", path=path, readonly=True)
    assert call("comments_list", path=path)["count"] == 1
    call("close_file", path=path)
    for tool in ("headers", "sections", "pe_info"):
        call(tool, path=str(pe))
    assert call("symbols", path=str(pe), kind="export")["count"] > 0
    call("symbols", path=str(pe), kind="import")
    pe_start = manifest["pe"]["symbols"]["_start"]
    pe_va = int(pe_start["va"], 16)
    call("address_translate", path=str(pe), address=hex(pe_va))
    call("address_translate", path=str(pe), address=hex(pe_va - 0x140000000), kind="rva")
    call("read_at_address", path=str(pe), address=hex(pe_va), length=16)
    call("elf_info", path=str(pe), error=True)
    call("close_file", path=str(pe))
    # Truncate extracted raw data, never an executable that may be running or mapped.
    raw = str(dump)
    call("open_file", path=raw, readonly=False)
    assert call("truncate", path=raw, offset=5, mode="after")["new_size"] == 6
    assert call("truncate", path=raw, offset=3, mode="before")["new_size"] == 3
    call("close_file", path=raw)
    assert dump.read_bytes() == b"DEM"
    assert call("logs_tail", limit=10)["count"] > 0
    call("logs_clear")
    assert client.used == client.available, ("Uncovered tools", client.available - client.used)
    print("PASS: all 39 MCP tools; ELF/PE inspection, encodings, signatures, edits, sidecar and truncation")
    print("PASS: saved gate patch changes Linux output" if execute else "Native ELF execution skipped")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, default=HERE.parents[1] / "target/debug/dz6-mcp")
    parser.add_argument("--skip-execution", action="store_true")
    args = parser.parse_args()
    assert args.server.is_file(), "Build dz6-mcp first or pass --server /absolute/path/to/dz6-mcp"
    execute = not args.skip_execution and platform.system() == "Linux" and platform.machine() == "x86_64"
    with tempfile.TemporaryDirectory(prefix="dz6-demo-check-") as tmp:
        with (Path(tmp) / "stderr.log").open("w+") as stderr:
            client = Client(args.server.resolve(), stderr)
            try:
                exercise(client, Path(tmp), execute)
            finally:
                client.close()


if __name__ == "__main__":
    main()
