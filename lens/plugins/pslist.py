"""Container processes: tasks judged owned, grouped into processes."""
from __future__ import annotations

from ..render import Result

NAME = "pslist"
HELP = "container processes (owned tasks), one row per process or per thread"
COLS = ["pid", "nspid", "ppid", "comm", "threads", "state", "uid", "ownership", "basis",
        "start_s"]
TCOLS = ["pid", "tgid", "nspid", "comm", "state", "lifecycle", "ownership", "basis", "task"]


def add_args(ap) -> None:
    ap.add_argument("--threads", action="store_true", help="one row per thread")
    ap.add_argument("--strict", action="store_true",
                    help="only tasks with definitive or page-table evidence")


def run(s, args) -> Result:
    owned = s.owned(include_likely=not args.strict)
    if args.threads:
        rows = [t.row() for t in owned]
        return Result("pslist (threads)", TCOLS, rows, meta={"threads": len(rows)})
    rows = []
    for p in s.processes(owned):
        r = p.row()
        r["pid"] = p.tgid
        r["threads"] = len(getattr(p, "_threads", [p]))
        if p.pid != p.tgid:
            # leader's task_struct not recovered: the row stands on a thread,
            # whose nspid is a thread id, not the process's PID
            r["nspid"] = None
            r["comm"] = p.comm + " (leader not in dump)"
        rows.append(r)
    notes = []
    if not rows and s.tasks():
        notes.append("tasks were found but none could be attributed to the target; "
                     "see psscan for the co-resident ones")
    if any(r["basis"].startswith("vmas=") for r in rows):
        notes.append("'vmas=N' is heuristic ownership (no page tables or ownership map in "
                     "this capture); v2 captures make it definitive")
    return Result("pslist", COLS, rows, notes, {"processes": len(rows), "threads": len(owned)})
