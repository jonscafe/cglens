"""Name file-backed VMAs from the process's own dynamic linker state.

When the kernel's record of a mapping's file is not in the dump (the struct
file charged elsewhere, the read-only page cache pages charged to whichever
cgroup read them first), the process itself still knows what it loaded. The
dynamic linker keeps a `struct link_map` per loaded object:

    struct link_map {
        ElfW(Addr)       l_addr;   // load bias
        char            *l_name;   // absolute path of the object
        ElfW(Dyn)       *l_ld;     // its .dynamic section, inside its own mapping
        struct link_map *l_next, *l_prev;
    };

These live in writable anonymous memory, which is the memory a container dump
does hold. The search runs backwards from the evidence: find path-like strings
ending in a shared object name in the process's captured pages, find pointers
to those strings, and treat each pointer as a candidate l_name. A candidate is
kept only if its l_ld falls inside a mapping of the process and its l_next /
l_prev agree with a neighbour, which a stray pointer does not satisfy.

l_ld then says which VMA (and so which vm_file pointer) belongs to the object,
and every VMA sharing that vm_file gets the name. The main executable has an
empty l_name; it is named from mm->exe_file instead.

This is userspace data and the report labels it so ("via link_map"): it is
what the process believed it loaded, not what the kernel recorded.
"""
from __future__ import annotations

import bisect
import re
import sys
from array import array
from itertools import compress

from ..core.layers import PAGE, AddressSpace, iter_user_pages

SO_PATH = re.compile(rb"/[\x21-\x7e]{1,240}?\.so(?:\.[0-9A-Za-z_.]+)?\x00")


def captured_pages(a: AddressSpace, vmas, writable_only: bool = True):
    """(va, bytes) for every captured page of the given VMAs.

    Walks the page tables once, top down, instead of translating every page
    of every VMA: glibc reserves 64 MiB per malloc arena and most of it is
    never touched, so a per-page walk spends its time on empty ranges.
    """
    spans = sorted((v.start, v.end) for v in vmas
                   if not v.stale and (not writable_only or v.flags & 0x2))
    if not spans:
        return
    starts = [s for s, _ in spans]
    for va, pa, _sz in iter_user_pages(a):
        k = bisect.bisect_right(starts, va) - 1
        if k < 0 or va >= spans[k][1]:
            continue
        data = a.phys.read(pa, PAGE)
        if data is not None:
            yield va, data


def recover(a: AddressSpace, vmas) -> list[dict]:
    pages = dict(captured_pages(a, vmas))
    # all captured pages, for strings that sit in read-only memory
    strings: dict[int, str] = {}
    for va, data in pages.items():
        for m in SO_PATH.finditer(data):
            strings[va + m.start()] = m.group()[:-1].decode("ascii", "replace")
    if not strings:
        return []

    def in_vma(p: int):
        for v in vmas:
            if not v.stale and v.start <= p < v.end:
                return v
        return None

    def q(va: int) -> int | None:
        page = pages.get(va & ~0xFFF)
        o = va & 0xFFF
        if page is None or o + 8 > PAGE:
            data, holes = a.read(va, 8)
            return None if holes else int.from_bytes(data, "little")
        return int.from_bytes(page[o:o + 8], "little")

    # Every aligned qword of every captured page is tested against the set of
    # string addresses in one C-level pass. (One bytes.find per string per
    # page cost 3 million calls and 20 s on a 77 MiB capture.)
    vas = list(pages)
    words = array("Q")
    words.frombytes(b"".join(pages[v] for v in vas))
    if sys.byteorder != "little":
        words.byteswap()
    per = PAGE // 8
    cands: dict[int, dict] = {}
    for i in compress(range(len(words)), map(strings.__contains__, words)):
        name = strings[words[i]]
        lm = vas[i // per] + (i % per) * 8 - 8      # l_name is the second member
        l_ld, nxt, prv = q(lm + 16), q(lm + 24), q(lm + 32)
        v = in_vma(l_ld) if l_ld else None
        if v is not None and v.file:
            cands[lm] = {"lm": lm, "name": name, "l_addr": q(lm),
                         "l_ld": l_ld, "next": nxt, "prev": prv,
                         "vm_file": v.file}
    # chain agreement: a real entry is linked from, or links to, another one
    out = []
    for lm, c in cands.items():
        linked = (c["next"] in cands and cands[c["next"]]["prev"] == lm) or \
                 (c["prev"] in cands and cands[c["prev"]]["next"] == lm) or \
                 (c["prev"] and q(c["prev"] + 24) == lm)
        if linked:
            out.append(c)
    return out


AT_NULL, AT_BASE, AT_EXECFN = 0, 7, 31


def saved_auxv(mm) -> dict[int, int]:
    """mm->saved_auxv: the aux vector the kernel built at exec, kept in mm_struct."""
    raw = mm.bytes("saved_auxv") if mm and mm.has("saved_auxv") else None
    out: dict[int, int] = {}
    for i in range(0, len(raw or b"") - 15, 16):
        t = int.from_bytes(raw[i:i + 8], "little")
        if t == AT_NULL:
            break
        out[t] = int.from_bytes(raw[i + 8:i + 16], "little")
    return out


def user_cstr(a: AddressSpace, va: int | None, maxlen: int = 4096) -> str | None:
    """NUL-terminated string in user memory, or None if it runs into a hole."""
    if not va:
        return None
    out = b""
    while len(out) < maxlen:
        take = PAGE - (va & 0xFFF)
        data, holes = a.read(va, take)
        if holes:
            return None
        nul = data.find(b"\x00")
        if nul >= 0:
            return (out + data[:nul]).decode("utf-8", "replace")
        out += data
        va += take
    return None


def exe_name(a: AddressSpace | None, mm) -> tuple[str, str] | None:
    """Name of the main executable from the process's own exec record.

    AT_EXECFN is the path given to execve(). For a #! script that is the
    SCRIPT; the mapped executable is the interpreter, which binfmt_script put
    in argv[0], with the script path following it (after one optional
    interpreter argument). Both strings sit on the captured stack.
    """
    if a is None or not mm:
        return None
    fn = user_cstr(a, saved_auxv(mm).get(AT_EXECFN))
    if not fn:
        return None
    lo, hi = mm.int("arg_start"), mm.int("arg_end")
    argv: list[str] = []
    if lo and hi and 0 < hi - lo < 1 << 20:
        data, holes = a.read(lo, hi - lo)
        if not holes:
            argv = [x.decode("utf-8", "replace") for x in data.rstrip(b"\x00").split(b"\x00")]
    if len(argv) > 1 and argv[0] != fn and fn in argv[1:3] and argv[0].startswith("/"):
        return argv[0], "shebang"
    return fn, "execfn"


def name_vmas(k, a: AddressSpace | None, mm_va: int, vmas) -> dict:
    """Fill in paths for VMAs whose file is not otherwise known. Returns stats."""
    from ..core import objects as ko
    todo = [v for v in vmas if v.file and not v.path_via and not v.stale]
    stats = {"unnamed_before": len(todo), "exe_file": 0, "execfn": 0, "shebang": 0,
             "link_map": 0, "auxv": 0}
    if not todo:
        return stats
    mm = k.obj("mm_struct", mm_va)
    by_file: dict[int, tuple[str, str]] = {}
    code = mm.int("start_code") if mm else None
    host = next((v for v in vmas if code and v.start <= code < v.end and v.file), None)
    if host:
        fp = ko.file_path(k, mm.ptr("exe_file")) if mm.has("exe_file") else None
        if fp and fp["path"] == ko.BROKEN + "/":
            fp = None               # struct file captured, not one dentry of its path
        if fp and fp["complete"]:
            by_file[host.file] = (fp["path"], "exe_file")
        else:
            # kernel record partial or absent: the process's exec record, unless
            # the kernel's partial path disagrees with it about the file name
            ex = exe_name(a, mm)
            leaf = fp["path"].rsplit("/", 1)[-1] if fp else None
            if ex and (leaf is None or ex[0].rsplit("/", 1)[-1] == leaf):
                by_file[host.file] = ex
            elif fp:
                by_file[host.file] = (fp["path"], "exe_file")
    if a is not None:
        for c in recover(a, vmas):
            by_file.setdefault(c["vm_file"], (c["name"], "link_map"))
    # the program interpreter (ld.so) is loaded at AT_BASE; its link_map name
    # points into the executable's read-only page, which is rarely captured
    base = saved_auxv(mm).get(AT_BASE) if mm else None
    interp = next((v for v in vmas if base and v.start == base and v.file), None)
    if interp and interp.file not in by_file:
        by_file[interp.file] = ("<program interpreter at AT_BASE; name not captured>", "auxv")
    for v in todo:
        hit = by_file.get(v.file)
        if hit:
            v.path, v.path_via = hit
            v.path_complete = hit[1] == "exe_file"
            stats[hit[1]] += 1
    stats["unnamed_after"] = sum(1 for v in todo if not v.path_via)
    return stats
