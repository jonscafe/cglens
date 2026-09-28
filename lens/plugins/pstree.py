"""Parent/child tree of container processes."""
from __future__ import annotations

from ..render import Result

NAME = "pstree"
HELP = "process tree of the container (parents outside the container shown as roots)"


def add_args(ap) -> None:
    pass


def run(s, args) -> Result:
    procs = s.processes()
    by_pid = {p.tgid: p for p in procs}
    kids: dict[int | None, list] = {}
    for p in procs:
        parent = p.ppid if p.ppid in by_pid and p.ppid != p.tgid else None
        kids.setdefault(parent, []).append(p)
    rows = []

    def walk(p, depth):
        rows.append({"tree": "  " * depth + ("└ " if depth else "") + p.comm,
                     "pid": p.tgid, "nspid": p.nspid, "ppid": p.ppid,
                     "threads": len(getattr(p, "_threads", [p]))})
        for c in sorted(kids.get(p.tgid, []), key=lambda x: x.tgid):
            walk(c, depth + 1)

    for root in sorted(kids.get(None, []), key=lambda x: x.tgid):
        walk(root, 0)
    return Result("pstree", ["tree", "pid", "nspid", "ppid", "threads"], rows)
