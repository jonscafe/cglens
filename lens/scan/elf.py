"""ELF objects in process memory, and rebuilding them from their loaded segments.

The loader maps each PT_LOAD segment at load_bias + p_vaddr. Reading those
ranges back through the process's page tables and writing each one at its
p_offset rebuilds the file's loadable image, which is what an analyst needs
from an implant that only ever existed in memory (memfd, reflective loading).

What cannot be recovered is said so: section headers usually sit past the last
loaded byte and are never mapped; writable segments carry relocations and
runtime data, not the bytes on disk; pages never touched were never loaded.
"""
from __future__ import annotations

import struct

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
ET_EXEC, ET_DYN = 2, 3


def parse_header(data: bytes) -> dict | None:
    if len(data) < 64 or data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1:
        return None          # ELF64 little endian only (x86_64)
    (e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _f, _eh, e_phentsize, e_phnum,
     _sh, e_shnum, _shs) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if e_phentsize != 56 or not 0 < e_phnum < 128:
        return None
    return {"type": e_type, "machine": e_machine, "entry": e_entry, "phoff": e_phoff,
            "phnum": e_phnum, "shoff": e_shoff, "shnum": e_shnum}


def program_headers(data: bytes, hdr: dict) -> list[dict]:
    out = []
    for i in range(hdr["phnum"]):
        o = hdr["phoff"] + i * 56
        if o + 56 > len(data):
            break
        p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_align = \
            struct.unpack_from("<IIQQQQQQ", data, o)
        out.append({"type": p_type, "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr,
                    "filesz": p_filesz, "memsz": p_memsz, "align": p_align})
    return out


def rebuild(aspace, base: int, max_bytes: int = 256 << 20) -> tuple[bytes, dict] | None:
    """Rebuild the loadable image of the ELF whose header is mapped at `base`."""
    head, holes = aspace.read(base, 4096)
    if holes:
        return None
    hdr = parse_header(head)
    if hdr is None:
        return None
    phs = program_headers(head, hdr)
    loads = [p for p in phs if p["type"] == PT_LOAD]
    if not loads:
        return None
    min_vaddr = min(p["vaddr"] for p in loads) & ~0xFFF
    bias = base - min_vaddr if hdr["type"] == ET_DYN else 0
    size = max(p["offset"] + p["filesz"] for p in loads)
    if size > max_bytes:
        return None
    out = bytearray(size)
    report = {"type": {ET_EXEC: "EXEC", ET_DYN: "DYN"}.get(hdr["type"], str(hdr["type"])),
              "entry": hex(hdr["entry"] + bias if hdr["type"] == ET_DYN else hdr["entry"]),
              "load_bias": hex(bias), "size": size, "segments": [],
              "section_headers_mapped": hdr["shoff"] + hdr["shnum"] * 64 <= size}
    for p in loads:
        data, sholes = aspace.read(bias + p["vaddr"], p["filesz"])
        out[p["offset"]:p["offset"] + p["filesz"]] = data
        missing = sum(h[1] for h in sholes)
        report["segments"].append({
            "vaddr": hex(bias + p["vaddr"]), "offset": p["offset"], "filesz": p["filesz"],
            "flags": ("r" if p["flags"] & 4 else "-") + ("w" if p["flags"] & 2 else "-")
            + ("x" if p["flags"] & 1 else "-"),
            "bytes_missing": missing,
            "note": "writable: relocated/runtime data, not the on-disk bytes"
            if p["flags"] & 2 else ""})
    report["bytes_missing"] = sum(sg["bytes_missing"] for sg in report["segments"])
    return bytes(out), report
