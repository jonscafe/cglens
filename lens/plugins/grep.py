"""Search the dump and attribute every hit (vol3 yarascan-style, without YARA)."""
from __future__ import annotations

import re

from ..render import Result
from ..scan.rmap import ReverseMap

NAME = "grep"
HELP = ("search strings / hex / regex across the dump; each hit attributed to a process "
        "address, a file offset, or a kernel object")


def add_args(ap) -> None:
    ap.add_argument("-s", "--string", action="append", default=[], help="literal string")
    ap.add_argument("-x", "--hex", action="append", default=[], help="hex bytes, e.g. 7f454c46")
    ap.add_argument("-r", "--regex", action="append", default=[], help="bytes regex")
    ap.add_argument("--utf16", action="store_true", help="also search strings as UTF-16LE")
    ap.add_argument("-i", "--ignore-case", action="store_true")
    ap.add_argument("--max-hits", type=int, default=500)
    ap.add_argument("--context", type=int, default=24, help="bytes of context around a hit")
    ap.add_argument("--no-files", action="store_true",
                    help="skip page cache attribution (faster on large captures)")


def _patterns(args) -> list[tuple[str, bytes]]:
    pats = []
    for st in args.string:
        pats.append((st, re.escape(st.encode())))
        if args.utf16:
            pats.append((st + " (utf16)", re.escape(st.encode("utf-16-le"))))
    for hx in args.hex:
        pats.append(("hex:" + hx, re.escape(bytes.fromhex(hx.replace(" ", "")))))
    for rx in args.regex:
        pats.append(("re:" + rx, rx.encode()))
    return pats


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 0x20 <= c < 0x7F else "." for c in b)


def run(s, args) -> Result:
    pats = _patterns(args)
    if not pats:
        raise SystemExit("grep: give at least one --string, --hex or --regex")
    phys = s.img.phys
    flags = re.IGNORECASE if args.ignore_case else 0
    rm = ReverseMap(s, files=not args.no_files)
    rows, total = [], 0
    for label, pat in pats:
        for m in re.finditer(pat, phys.buf, flags):
            pa = phys.file_to_pa(m.start())
            if pa is None or phys.file_to_pa(m.end() - 1) != pa + (m.end() - 1 - m.start()):
                continue            # inside a LiME header, or across two ranges
            total += 1
            if len(rows) >= args.max_hits:
                continue
            c0 = max(m.start() - args.context, 0)
            ctx = _printable(bytes(phys.buf[c0:m.end() + args.context]))
            for att in rm.attribute(pa):
                rows.append({"pattern": label, "pa": hex(pa), **att, "context": ctx})
    notes = [f"reverse map: {rm.stats['process_pages']} process pages, "
             f"{rm.stats['file_pages']} page cache pages"]
    if total > len({r['pa'] for r in rows}):
        notes.append(f"{total} hits in total; raise --max-hits to see more")
    return Result("grep", ["pattern", "pa", "kind", "pid", "comm", "va", "where", "context"],
                  rows, notes, {"hits": total})
