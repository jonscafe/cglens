"""Every task_struct found in the dump, owned or not, with the ownership basis."""
from __future__ import annotations

from ..render import Result

NAME = "psscan"
HELP = "all task_struct objects in the dump, including co-resident and exited ones"
COLS = ["pid", "tgid", "nspid", "ppid", "comm", "state", "lifecycle", "ownership",
        "basis", "task"]


def add_args(ap) -> None:
    ap.add_argument("--stride", type=int, default=None,
                    help="scan stride in bytes (default 64, the task_struct alignment)")


def run(s, args) -> Result:
    if getattr(args, "stride", None):
        s.stride = args.stride
    tasks = s.tasks()
    rows = [t.row() for t in tasks]
    hist: dict[str, int] = {}
    for t in tasks:
        hist[t.ownership] = hist.get(t.ownership, 0) + 1
    meta = {"tasks": len(tasks), "by_ownership": hist, "scan": s.scan_stats}
    notes = ["co-resident tasks share a captured slab page with the target; they "
             "are real objects of other cgroups (or the host), not container members"]
    return Result("psscan", COLS, rows, notes, meta)
