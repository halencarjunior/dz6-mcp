#!/usr/bin/env python3
"""Build ELF/PE teaching fixtures using Python 3 and GNU binutils."""
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
OUT = HERE / "bin"
SYMBOLS = (
    "_start", "check_gate", "patch_pad", "demo_magic", "number_le", "signed_value",
    "greeting_utf8", "greeting_latin1", "greeting_utf16le", "greeting_utf16be",
    "signature_lab", "entropy_ramp", "zero_pad", "demo_gate", "scratch_buffer",
)


def run(*args):
    return subprocess.check_output(args, text=True)


def describe(path):
    sections = []
    for line in run("objdump", "-h", str(path)).splitlines():
        parts = line.split()
        if len(parts) >= 7 and parts[0].isdigit():
            sections.append((parts[1], int(parts[2], 16), int(parts[3], 16),
                             int(parts[5], 16)))
    symbols = {}
    for line in run("nm", "-n", str(path)).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in SYMBOLS:
            va = int(parts[0], 16)
            owner = next((s for s in sections if s[2] <= va < s[2] + s[1]), None)
            symbols[parts[2]] = {
                "va": hex(va),
                "offset": owner[3] + va - owner[2] if owner and owner[0] != ".bss" else None,
                "section": owner[0] if owner else None,
            }
    assert set(symbols) == set(SYMBOLS), symbols
    return {"file": path.name, "size": path.stat().st_size, "symbols": symbols}


def main():
    OUT.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dz6-assembly-") as tmp:
        obj = str(Path(tmp) / "demo.o")
        run("as", "--64", "-o", obj, str(HERE / "demo.s"))
        run("ld", "-m", "elf_x86_64", "--build-id=sha1", "-z", "noexecstack",
            "-e", "_start", "-o", str(OUT / "demo.elf"), obj)
        run("as", "--64", "--defsym", "PE=1", "-o", obj, str(HERE / "demo.s"))
        run("ld", "-m", "i386pep", "--no-insert-timestamp", "--export-all-symbols",
            "--subsystem", "console", "-e", "_start", "-o", str(OUT / "demo.exe"), obj)
    manifest = {fmt: describe(OUT / name) for fmt, name in
                (("elf", "demo.elf"), ("pe", "demo.exe"))}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Built demo.elf, demo.exe and manifest.json in", OUT)


if __name__ == "__main__":
    main()
