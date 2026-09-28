"""Executable memory that did not come from a file on disk (vol3 linux.malfind)."""
from __future__ import annotations

from ..render import Result
from ..scan import elf as elfmod

NAME = "malfind"
HELP = "suspicious executable mappings: anonymous, writable+executable, memfd or deleted backed"

VM_WRITE, VM_EXEC = 0x2, 0x4
BENIGN_KINDS = ("[vdso]", "[vvar]")


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append")
    ap.add_argument("--all-tasks", action="store_true")
    ap.add_argument("--bytes", type=int, default=64, help="bytes of preview (default 64)")


def hexdump(data: bytes, base: int, width: int = 16) -> list[str]:
    out = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        out.append(f"{base + i:#014x}  {hx:<{width * 3}} {asc}")
    return out


def reasons(v) -> list[str]:
    r = []
    if not v.flags & VM_EXEC or v.kind in BENIGN_KINDS:
        return r
    if v.flags & VM_WRITE:
        r.append("write+exec")
    if not v.file:
        r.append("anonymous-exec")
    path = v.path or ""
    if "memfd:" in path:
        r.append("memfd-exec")
    elif path.endswith("(deleted)"):
        r.append("deleted-file-exec")
    return r


def run(s, args) -> Result:
    rows, notes = [], []
    for p in s.select(args.pid, args.all_tasks):
        a = s.aspace(p)
        for v in s.vmas(p.mm) if p.mm else []:
            if v.stale:
                continue
            why = reasons(v)
            if not why:
                continue
            preview, first = [], None
            if a is not None:
                # first captured page of the region
                va = v.start
                while va < v.end and va < v.start + (64 << 12):
                    t = a.translate(va)
                    if t.ok:
                        first = va
                        break
                    va += 4096
                if first is not None:
                    data, _h = a.read(first, args.bytes)
                    preview = hexdump(data, first)
                    if data[:4] == elfmod.ELF_MAGIC:
                        why.append("elf-header")
                    elif not any(data):
                        why.append("zero-filled")
            rows.append({"pid": p.tgid, "comm": p.comm, "start": hex(v.start),
                         "end": hex(v.end), "perms": v.perms,
                         "path": v.path or v.kind or "[anon]", "reasons": ",".join(why),
                         "resident": (v.resident or {}).get("ok") if v.resident else None,
                         "preview": "\n".join(preview) if preview else "(no captured page)"})
    notes.append("JIT runtimes (JVM, V8, .NET, PyPy) legitimately hold anonymous executable "
                 "memory; judge a hit by the process, the contents and the other reasons")
    return Result("malfind", ["pid", "comm", "start", "end", "perms", "reasons", "path",
                              "preview"], rows, notes, {"hits": len(rows)})
