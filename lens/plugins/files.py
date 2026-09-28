"""Files the container touched: every inode in the dump, with its page cache."""
from __future__ import annotations

from collections import Counter

from ..render import Result
from ..scan.inodes import PageCacheWalker

NAME = "files"
HELP = ("inodes in the dump (open, mapped, or merely cached) with how much of their "
        "page cache was captured")
COLS = ["ino", "type", "size", "nlink", "cached", "captured", "owner", "deleted", "path",
        "inode"]


def add_args(ap) -> None:
    ap.add_argument("--all", action="store_true",
                    help="include inodes of other cgroups that share captured slab pages")
    ap.add_argument("--type", help="only this file type (reg, dir, link, sock, fifo, chr)")
    ap.add_argument("--path", help="only paths containing this substring")


def owner_of(s, inode, captured: int) -> str:
    sm = s.img.slabmap
    if sm is not None:
        own = sm.owned(inode.va)
        if own is True:
            return "objcg"
        if own is False:
            return "foreign" if not captured else "foreign-obj+pages"
    return "pages" if captured else "unknown"


def run(s, args) -> Result:
    w = PageCacheWalker(s.k)
    rows = []
    hist: Counter = Counter()
    for i in s.inodes():
        if args.type and i.ftype != args.type:
            continue
        if args.path and args.path not in i.path:
            continue
        captured = 0
        if i.nrpages:
            last = max(i.size - 1, 0) >> 12
            captured = sum(1 for _x, _p, st in w.walk(i.va, last) if st == "ok")
        owner = owner_of(s, i, captured)
        hist[owner] += 1
        if not args.all and owner not in ("objcg", "pages", "foreign-obj+pages"):
            continue
        rows.append({"ino": i.ino, "type": i.ftype, "size": i.size, "nlink": i.nlink,
                     "cached": i.nrpages, "captured": captured, "owner": owner,
                     "deleted": i.deleted, "path": i.path or "<no dentry captured>",
                     "inode": hex(i.va)})
    notes = ["'cached' is the inode's own page count (nrpages); 'captured' is how many of "
             "those pages are in the dump",
             "owner: objcg = v2 ownership map says the inode object is the container's; "
             "pages = its page cache pages were charged to the container (captured)"]
    if not s.img.slabmap:
        notes.append("no ownership map (pre-v2 capture): inodes without captured pages are "
                     "hidden unless --all")
    return Result("files", COLS, rows, notes,
                  {"inodes_in_dump": len(s.inodes()), "listed": len(rows),
                   "by_owner": dict(hist), "scan": s.inode_stats})
