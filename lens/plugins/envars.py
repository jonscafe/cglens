"""Environment of container processes (the initial environ block on the stack)."""
from __future__ import annotations

from ..render import Result
from .cmdline import read_mm_range

NAME = "envars"
HELP = "process environment (mm->env_start..env_end), one row per variable"


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append")
    ap.add_argument("--all-tasks", action="store_true")


def run(s, args) -> Result:
    rows = []
    notes = ["this is the environment the process was started with; setenv() after "
             "start does not rewrite this block"]
    for p in s.select(args.pid, args.all_tasks):
        data, _h, status = read_mm_range(s, p, "env_start", "env_end")
        if not data:
            rows.append({"pid": p.tgid, "comm": p.comm, "variable": None, "value": None,
                         "status": status})
            continue
        for kv in data.rstrip(b"\x00").split(b"\x00"):
            if not kv:
                continue
            k_, _, v = kv.decode("utf-8", "replace").partition("=")
            rows.append({"pid": p.tgid, "comm": p.comm, "variable": k_, "value": v,
                         "status": status})
    return Result("envars", ["pid", "comm", "variable", "value", "status"], rows, notes)
