"""VMAs of container processes, recovered by pointer-anchored search."""
from __future__ import annotations

from ..render import Result

NAME = "maps"
HELP = "memory map of a process (VMAs), with how much of each is in the dump"
COLS = ["pid", "start", "end", "perms", "pgoff", "size_kb", "in_dump", "pages", "via", "path",
        "stale"]


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append",
                    help="host PID, TGID or namespaced PID (repeatable; default: all)")
    ap.add_argument("--all-tasks", action="store_true",
                    help="include co-resident (non-owned) tasks")
    ap.add_argument("--stale", action="store_true", help="include stale (freed) VMAs")


def run(s, args) -> Result:
    rows = []
    notes = []
    no_pt = []
    for p in s.select(args.pid, args.all_tasks):
        if not p.mm:
            continue
        a = s.aspace(p)
        if a is None:
            no_pt.append(p.tgid)
        for v in s.vmas(p.mm):
            if v.stale and not args.stale:
                continue
            if a is not None and v.resident is None:
                v.resident = a.residency(v.start, v.end)
            r = v.row()
            r["pid"] = p.tgid
            rows.append(r)
    if no_pt:
        notes.append(f"no page tables in the dump for pid(s) {no_pt}: VMAs are listed, "
                     "residency is unknown")
    via: dict[str, int] = {}
    for r in rows:
        if r["via"] or (r["path"] or "").startswith("<file"):
            via[r["via"] or "unnamed"] = via.get(r["via"] or "unnamed", 0) + 1
    if via.get("link_map"):
        notes.append("'link_map' paths come from the process's dynamic linker state "
                     "(userspace data), not from kernel records")
    if via.get("execfn") or via.get("shebang"):
        notes.append("'execfn' is the path given to execve() (AT_EXECFN on the process "
                     "stack); 'shebang' is the #! interpreter binfmt_script put in argv[0]. "
                     "Both are userspace data")
    return Result("maps", COLS, rows, notes, {"vmas": len(rows), "file_vma_naming": via})
