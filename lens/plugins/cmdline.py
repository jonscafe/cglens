"""Command line of container processes, read through their own page tables."""
from __future__ import annotations

from ..render import Result

NAME = "cmdline"
HELP = "process command lines (mm->arg_start..arg_end through the process page tables)"
MAX_ARGS = 1 << 20


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append")
    ap.add_argument("--all-tasks", action="store_true")


def read_mm_range(s, p, start_field: str, end_field: str):
    """(bytes, holes, status). status explains an empty result."""
    if not p.mm:
        return None, [], "no mm (kernel thread or exited)"
    mm = s.k.obj("mm_struct", p.mm)
    if not mm:
        return None, [], "mm_struct not in dump"
    a = s.aspace(p)
    if a is None:
        return None, [], "page tables not in dump"
    lo, hi = mm.int(start_field), mm.int(end_field)
    if not lo or not hi or hi <= lo or hi - lo > MAX_ARGS:
        return None, [], f"bad range {lo}-{hi}"
    data, holes = a.read(lo, hi - lo)
    status = "ok" if not holes else "partial: " + ",".join(sorted({h[2] for h in holes}))
    return data, holes, status


def run(s, args) -> Result:
    rows = []
    for p in s.select(args.pid, args.all_tasks):
        data, _holes, status = read_mm_range(s, p, "arg_start", "arg_end")
        args_ = []
        if data:
            args_ = [x.decode("utf-8", "replace") for x in data.rstrip(b"\x00").split(b"\x00")]
        rows.append({"pid": p.tgid, "nspid": p.nspid, "comm": p.comm,
                     "cmdline": " ".join(args_) if args_ else None, "status": status})
    return Result("cmdline", ["pid", "nspid", "comm", "status", "cmdline"], rows)
