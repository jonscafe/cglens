"""Rebuild files from the page cache captured in the dump."""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter

from ..render import Result
from ..scan.inodes import PageCacheWalker, pagemeta_index

NAME = "filedump"
HELP = "reconstruct files from captured page cache (by path, inode number, or all)"
PAGE = 4096


def add_args(ap) -> None:
    ap.add_argument("-D", "--dump-dir", required=True)
    ap.add_argument("--path", help="files whose path contains this substring")
    ap.add_argument("--ino", type=int, action="append", help="inode number (repeatable)")
    ap.add_argument("--inode", action="append", help="inode virtual address (repeatable)")
    ap.add_argument("--all-cached", action="store_true",
                    help="every file with at least one captured page")
    ap.add_argument("--max-mib", type=int, default=256, help="skip files larger than this")


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)[-80:] or "noname"


def _ranges(indices: list[int]) -> list[list[int]]:
    out: list[list[int]] = []
    for i in sorted(indices):
        if out and out[-1][1] + 1 == i:
            out[-1][1] = i
        else:
            out.append([i, i])
    return out


def run(s, args) -> Result:
    if not (args.path or args.ino or args.inode or args.all_cached):
        raise SystemExit("filedump: choose --path, --ino, --inode or --all-cached")
    os.makedirs(args.dump_dir, exist_ok=True)
    k = s.k
    w = PageCacheWalker(k)
    pmi = pagemeta_index(k)
    want_va = {int(x, 16) for x in (args.inode or [])}
    want_ino = set(args.ino or [])
    rows, report = [], []
    for i in s.inodes():
        if i.ftype not in ("reg", "link") or not i.nrpages and i.va not in pmi:
            continue
        sel = (i.va in want_va or i.ino in want_ino
               or (args.path and args.path in i.path))
        if not sel and not args.all_cached:
            continue
        if i.size > args.max_mib << 20:
            continue
        npages = (i.size + PAGE - 1) // PAGE
        status: dict[int, str] = {}
        pfns: dict[int, int] = {}
        for idx, pfn, st in w.walk(i.va, max(npages - 1, 0)):
            if idx is None or idx >= npages:
                if idx is None:
                    status[-1] = st
                continue
            status[idx] = st
            if st == "ok":
                pfns[idx] = pfn
        # the independent path: struct page -> mapping/index (v2 captures)
        pm = {x: p for x, p in (pmi.get(i.va) or {}).items() if x < npages}
        disagree = sorted(x for x in set(pm) & set(pfns) if pm[x] != pfns[x])
        only_pm = sorted(set(pm) - set(pfns))
        for x in only_pm:
            pfns[x] = pm[x]
            status[x] = "ok-via-pagemeta"
        captured = len(pfns)
        if not captured and args.all_cached:
            continue
        buf = bytearray(i.size)
        for x, pfn in pfns.items():
            page = k.phys.read(pfn * PAGE, PAGE)
            if page is None:
                continue
            start = x * PAGE
            buf[start:start + PAGE] = page[: max(0, min(PAGE, i.size - start))]
        base = i.path.rsplit("/", 1)[-1] if i.path else "noname"
        fname = f"ino{i.ino}.{_safe(base)}"
        with open(os.path.join(args.dump_dir, fname), "wb") as f:
            f.write(buf)
        missing = [x for x in range(npages) if x not in pfns]
        reasons = Counter(status.get(x, "not-in-page-cache") for x in missing)
        sha = hashlib.sha256(buf).hexdigest()
        complete = not missing
        report.append({"file": fname, "path": i.path, "ino": i.ino, "inode": hex(i.va),
                       "size": i.size, "pages": npages, "captured_pages": captured,
                       "complete": complete, "sha256": sha if complete else None,
                       "sha256_zero_filled": sha, "deleted": i.deleted,
                       "missing_ranges": _ranges(missing)[:64],
                       "missing_reasons": dict(reasons),
                       "pagemeta": {"pages": len(pm), "disagree": disagree[:16],
                                    "only_pagemeta": len(only_pm)} if pmi else None})
        rows.append({"ino": i.ino, "size": i.size, "pages": f"{captured}/{npages}",
                     "complete": complete, "deleted": i.deleted,
                     "sha256": sha[:16] if complete else "-", "path": i.path, "file": fname})
    with open(os.path.join(args.dump_dir, "filedump.json"), "w") as f:
        json.dump(report, f, indent=1)
    notes = ["missing pages are zero filled; filedump.json lists each gap and why "
             "(not-in-page-cache, evicted-or-swapped, page-not-captured, xa-node-not-captured)",
             "sha256 is given only for complete files; sha256_zero_filled in the JSON "
             "covers the reconstruction as written"]
    return Result("filedump", ["ino", "size", "pages", "complete", "deleted", "sha256",
                               "path", "file"], rows, notes,
                  {"dump_dir": args.dump_dir, "files": len(rows)})
