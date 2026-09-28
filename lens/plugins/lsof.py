"""Open file descriptors of container processes (task->files->fdt->fd[])."""
from __future__ import annotations

from ..core.kernel import is_kptr
from ..core import objects as ko
from ..render import Result

NAME = "lsof"
HELP = "open file descriptors: files, sockets, pipes, memfds, deleted files"

S_IFMT = 0o170000
TYPES = {0o140000: "sock", 0o120000: "link", 0o100000: "reg", 0o060000: "blk",
         0o040000: "dir", 0o020000: "chr", 0o010000: "fifo"}
MAX_FDS = 65536


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append")
    ap.add_argument("--all-tasks", action="store_true")


def describe(k, fva):
    fp = ko.file_path(k, fva)
    if fp is None:
        return {"type": "?", "name": "<struct file not captured>", "inode": None,
                "deleted": None}
    f = k.obj("file", fva)
    mode = None
    iva = f.ptr("f_inode") if f.has("f_inode") else None
    ino = k.obj("inode", iva) if is_kptr(iva) else None
    if ino:
        mode = ino.int("i_mode")
    ftype = TYPES.get((mode or 0) & S_IFMT, "?") if mode is not None else "?"
    if fp["path"] == ko.BROKEN + "/" and mode is None:
        # The struct file is in the dump but neither its dentry nor its inode
        # is. Typical for the stdout/stderr pipes containerd-shim creates: the
        # file is charged to the shim and sits in a slab page captured for the
        # target's objects next to it, while pipefs inodes are elsewhere. Seen
        # on 7.1.5 (v71d). "…/" would read as a path; there is no name to give.
        return {"type": "?", "name": "<struct file captured, name not reachable>",
                "inode": fp["inode"], "deleted": None,
                "pos": f.int("f_pos") if f.has("f_pos") else None}
    name = fp["path"]
    base = name.rsplit("/", 1)[-1]
    if ftype == "sock":
        name = f"socket:[{fp['inode']}] {base}".rstrip()
    elif ftype == "fifo" and base == "":
        name = f"pipe:[{fp['inode']}]"     # pipefs names its dentries ""
    elif base.startswith("[") and base.endswith("]"):
        name = f"anon_inode:{base}"
    elif base.startswith("memfd:"):
        ftype = "memfd"
    if fp["deleted"] and not name.endswith("(deleted)") and ftype not in ("sock", "fifo"):
        name += " (deleted)"
    pos = f.int("f_pos") if f.has("f_pos") else None
    return {"type": ftype, "name": name, "inode": fp["inode"], "deleted": fp["deleted"],
            "pos": pos}


def run(s, args) -> Result:
    k = s.k
    rows = []
    notes = []
    for p in s.select(args.pid, args.all_tasks):
        t = k.obj("task_struct", p.va)
        files = t.deref("files", "files_struct") if t.has("files") else None
        if not files:
            notes.append(f"pid {p.tgid}: files_struct not in dump")
            continue
        fdt = files.deref("fdt", "fdtable")
        if not fdt:
            notes.append(f"pid {p.tgid}: fdtable not in dump")
            continue
        n = min(fdt.int("max_fds") or 0, MAX_FDS)
        arr_va = fdt.ptr("fd")
        raw = k.dmap.read(arr_va, n * 8) if is_kptr(arr_va) and n else None
        if raw is None:
            notes.append(f"pid {p.tgid}: fd array ({n} slots) not in the direct map "
                         "or not captured (large tables are vmalloc'd)")
            continue
        for fd in range(n):
            fva = int.from_bytes(raw[fd * 8:fd * 8 + 8], "little")
            if not fva:
                continue
            if not is_kptr(fva):
                continue
            d = describe(k, fva)
            rows.append({"pid": p.tgid, "comm": p.comm, "fd": fd, **d})
    return Result("lsof", ["pid", "comm", "fd", "type", "inode", "pos", "name"], rows, notes)
