"""ELF objects mapped in container processes (vol3 linux.elfs), optionally rebuilt."""
from __future__ import annotations

import json
import os
import re

from ..render import Result
from ..scan import elf as elfmod

NAME = "elfs"
HELP = "ELF headers at the start of mappings (files, memfds, anonymous memory); --dump rebuilds them"


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append")
    ap.add_argument("--all-tasks", action="store_true")
    ap.add_argument("-D", "--dump-dir", help="rebuild each ELF from its loaded segments here")
    ap.add_argument("--header-only", action="store_true",
                    help="list only objects whose ELF header is in the dump")


def _safe(x: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", x)[-60:] or "anon"


def run(s, args) -> Result:
    rows, notes, reports, missing = [], [], [], []
    if args.dump_dir:
        os.makedirs(args.dump_dir, exist_ok=True)
    for p in s.select(args.pid, args.all_tasks):
        a = s.aspace(p)
        if a is None:
            notes.append(f"pid {p.tgid}: page tables not in dump")
            continue
        seen_files: set[int] = set()
        for v in s.vmas(p.mm):
            if v.stale or (v.file and v.pgoff != 0):
                continue
            head, holes = a.read(v.start, 64)
            if holes or head[:4] != elfmod.ELF_MAGIC:
                # Header page never charged to the container (shared library
                # page cache). The object is still known to be loaded, by name,
                # when the mapping was named: list it, marked as such.
                if (not args.header_only and v.file and v.path_via
                        and v.file not in seen_files):
                    seen_files.add(v.file)
                    missing.append({"pid": p.tgid, "comm": p.comm, "start": hex(v.start),
                                    "end": hex(v.end), "kind": "file", "type": "?",
                                    "header": "not captured", "via": v.path_via,
                                    "path": v.path, "dumped": None})
                continue
            if v.file:
                seen_files.add(v.file)
            hdr = elfmod.parse_header(head + bytes(4096 - 64)) or {}
            kind = "file" if v.file else "anonymous"
            if "memfd:" in (v.path or ""):
                kind = "memfd"
            elif v.path.endswith("(deleted)"):
                kind = "deleted-file"
            row = {"pid": p.tgid, "comm": p.comm, "start": hex(v.start), "end": hex(v.end),
                   "kind": kind, "type": {2: "EXEC", 3: "DYN"}.get(hdr.get("type"), "?"),
                   "header": "in dump", "via": v.path_via,
                   "path": v.path or v.kind or "[anon]", "dumped": None}
            if args.dump_dir:
                got = elfmod.rebuild(a, v.start)
                if got:
                    data, rep = got
                    fname = f"pid.{p.tgid}.{v.start:x}.{_safe(v.path or 'anon')}.elf"
                    with open(os.path.join(args.dump_dir, fname), "wb") as f:
                        f.write(data)
                    rep.update({"pid": p.tgid, "start": hex(v.start), "path": v.path,
                                "file": fname})
                    reports.append(rep)
                    row["dumped"] = f"{fname} ({rep['bytes_missing']} bytes missing)"
            rows.append(row)
    if args.dump_dir:
        with open(os.path.join(args.dump_dir, "elfs.json"), "w") as f:
            json.dump(reports, f, indent=1)
        notes.append("rebuilt from PT_LOAD segments: section headers are rarely mapped, and "
                     "writable segments hold relocated runtime data")
    if missing:
        notes.append("header 'not captured': the object's first page was charged to another "
                     "cgroup (shared image layer page cache). It is listed from its mapping's "
                     "name (see 'via'); type and segments are unknown and it cannot be rebuilt")
    elif not args.header_only:
        notes.append("an ELF whose first page is not in the dump and whose mapping has no "
                     "name is not listed")
    return Result("elfs", ["pid", "comm", "start", "end", "kind", "type", "header", "via",
                           "path", "dumped"],
                  rows + missing, notes,
                  {"elfs": len(rows) + len(missing), "header_in_dump": len(rows),
                   "header_not_captured": len(missing)})
