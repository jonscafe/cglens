"""Write a process's memory out, one file per VMA, with a hole map."""
from __future__ import annotations

import json
import os
import re

from ..render import Result

NAME = "procdump"
HELP = "dump process memory per VMA (holes zero filled and listed in a JSON map)"


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append", required=True)
    ap.add_argument("-D", "--dump-dir", required=True)
    ap.add_argument("--all-tasks", action="store_true")
    ap.add_argument("--max-vma-mib", type=int, default=512,
                    help="skip VMAs larger than this (default 512)")
    ap.add_argument("--address", type=lambda x: int(x, 0), action="append",
                    help="only the VMA(s) containing this virtual address (repeatable)")


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60]


def run(s, args) -> Result:
    os.makedirs(args.dump_dir, exist_ok=True)
    rows, notes = [], []
    for p in s.select(args.pid, args.all_tasks):
        a = s.aspace(p)
        if a is None:
            notes.append(f"pid {p.tgid}: page tables not in dump; nothing to dump")
            continue
        report = {"pid": p.tgid, "nspid": p.nspid, "comm": p.comm, "vmas": []}
        for v in s.vmas(p.mm):
            if v.stale:
                continue
            if args.address and not any(v.start <= a_ < v.end for a_ in args.address):
                continue
            size = v.end - v.start
            name = f"pid.{p.tgid}.{v.start:x}-{v.end:x}.{_safe(v.path or v.kind or 'anon')}.dmp"
            entry = {"start": hex(v.start), "end": hex(v.end), "perms": v.perms,
                     "path": v.path or v.kind, "file": name}
            if size > args.max_vma_mib << 20:
                entry["skipped"] = "too large"
                report["vmas"].append(entry)
                continue
            data, holes = a.read(v.start, size)
            if len(holes) == 1 and holes[0][1] == size:
                entry["skipped"] = f"nothing captured ({holes[0][2]})"
                report["vmas"].append(entry)
                continue
            with open(os.path.join(args.dump_dir, name), "wb") as f:
                f.write(data)
            got = size - sum(h[1] for h in holes)
            entry.update({"bytes_captured": got, "bytes_total": size,
                          "holes": [{"va": hex(h[0]), "len": h[1], "reason": h[2]} for h in holes]})
            report["vmas"].append(entry)
            rows.append({"pid": p.tgid, "vma": f"{v.start:x}-{v.end:x}", "perms": v.perms,
                         "captured_kb": got // 1024, "total_kb": size // 1024,
                         "path": v.path or v.kind, "file": name})
        with open(os.path.join(args.dump_dir, f"pid.{p.tgid}.map.json"), "w") as f:
            json.dump(report, f, indent=2)
    return Result("procdump", ["pid", "vma", "perms", "captured_kb", "total_kb", "path", "file"],
                  rows, notes, {"dump_dir": args.dump_dir})
