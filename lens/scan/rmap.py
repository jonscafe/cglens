"""Physical page -> who it belongs to: process address, file offset, kernel object.

A hit in a raw dump is a physical offset, which by itself says nothing. The
container's own page tables map its pages back to (pid, virtual address, VMA),
the page cache XArrays map file pages back to (file, offset), and a v2
capture's page classes and slab map name the kernel pages. One page can be
all at once (a mapped file page is both), and every attribution is listed.
"""
from __future__ import annotations

import bisect

from ..core.layers import iter_user_pages
from .inodes import PageCacheWalker, pagemeta_index

PAGE = 4096


class ReverseMap:
    def __init__(self, s, files: bool = True):
        self.s = s
        self.proc: dict[int, list[tuple]] = {}
        self.file: dict[int, list[tuple]] = {}
        self.stats = {"process_pages": 0, "file_pages": 0}
        self._vma_index: dict[int, tuple[list[int], list]] = {}
        for p in s.processes():
            a = s.aspace(p)
            if a is None:
                continue
            for va, pa, _sz in iter_user_pages(a):
                self.proc.setdefault(pa >> 12, []).append((p.tgid, p.comm, va, p.mm))
                self.stats["process_pages"] += 1
        if files:
            w = PageCacheWalker(s.k)
            pmi = pagemeta_index(s.k)
            for i in s.inodes():
                if not i.nrpages and i.va not in pmi:
                    continue
                last = max(i.size - 1, 0) >> 12
                for idx, pfn, st in w.walk(i.va, last):
                    if st == "ok":
                        self.file.setdefault(pfn, []).append((i.path, i.ino, idx))
                for idx, pfn in (pmi.get(i.va) or {}).items():
                    lst = self.file.setdefault(pfn, [])
                    if (i.path, i.ino, idx) not in lst:
                        lst.append((i.path, i.ino, idx))
            self.stats["file_pages"] = len(self.file)

    def _vma(self, mm: int, va: int):
        idx = self._vma_index.get(mm)
        if idx is None:
            vmas = [v for v in self.s.vmas(mm) if not v.stale]
            vmas.sort(key=lambda v: v.start)
            idx = self._vma_index[mm] = ([v.start for v in vmas], vmas)
        starts, vmas = idx
        k = bisect.bisect_right(starts, va) - 1
        if k >= 0 and vmas[k].start <= va < vmas[k].end:
            return vmas[k]
        return None

    def attribute(self, pa: int) -> list[dict]:
        pfn, off = pa >> 12, pa & 0xFFF
        out = []
        for pid, comm, va, mm in self.proc.get(pfn, ()):
            v = self._vma(mm, va)
            out.append({"kind": "process", "pid": pid, "comm": comm, "va": hex(va + off),
                        "where": (v.path or v.kind or "[anon]") if v else "?"})
        for path, ino, idx in self.file.get(pfn, ()):
            out.append({"kind": "file", "pid": None, "comm": None, "va": None,
                        "where": f"{path} +{idx * PAGE + off:#x} (ino {ino})"})
        if out:
            return out
        img = self.s.img
        cls = img.pagemeta.page_class(pfn) if img.pagemeta else None
        sm = img.slabmap
        hit = sm.lookup(img.page_offset_base + pa) if sm is not None else None
        if hit:
            name, obj, owned = hit
            return [{"kind": "slab", "pid": None, "comm": None, "va": None,
                     "where": f"{name}[{obj}] {'owned' if owned else 'other cgroup'}"}]
        return [{"kind": cls or "unattributed", "pid": None, "comm": None, "va": None,
                 "where": "" if cls else "no mapping found (unmapped anon, kernel, or "
                          "page cache of an inode not in the dump)"}]
