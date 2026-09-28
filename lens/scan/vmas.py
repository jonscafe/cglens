"""Recover a process's VMAs from a scoped dump.

From 6.1 the VMA set lives in a maple tree whose nodes come from a cache that
is not memcg accounted, so they are almost never in a container dump. The
vm_area_struct objects themselves ARE accounted (SLAB_ACCOUNT) and are there.

So the search is inverted, the same way pslist is: instead of walking a
structure down from mm_struct, find every object that points UP at it. Each
VMA carries vm_mm; the eight bytes of the mm_struct's address are searched for
across the whole dump at C speed, and every hit at the vm_mm offset is a
candidate VMA. Validation then rejects hits that belong to other structures.

Freed VMAs keep their vm_mm until the slab reuses them. They are reported,
not hidden, and marked stale by the kernel's own liveness signal where BTF
shows one (`detached` 6.4-6.14, `vm_refcnt` from 6.15) and by overlap with a
live VMA otherwise.

On kernels that still link VMAs (mm->mmap, before 6.1) the list is walked as
well and each VMA records which method found it.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..core.kernel import Kernel, is_kptr
from ..core import objects as ko

TASK_SIZE_MAX = (1 << 47) - 4096
TASK_SIZE_MAX_LA57 = (1 << 56) - 4096

VM_READ, VM_WRITE, VM_EXEC, VM_SHARED, VM_MAYSHARE = 0x1, 0x2, 0x4, 0x8, 0x80
VM_GROWSDOWN = 0x100


@dataclass
class Vma:
    va: int
    start: int
    end: int
    flags: int
    pgoff: int
    file: int
    path: str = ""
    path_complete: bool = True
    deleted: bool = False
    stale: bool = False
    stale_reason: str = ""
    found_by: str = "anchor"
    resident: dict | None = None
    kind: str = ""
    path_via: str = ""      # "file" (vm_file) or "pagecache" (struct page -> inode)

    @property
    def perms(self) -> str:
        f = self.flags
        return ("r" if f & VM_READ else "-") + ("w" if f & VM_WRITE else "-") + \
               ("x" if f & VM_EXEC else "-") + ("s" if f & VM_MAYSHARE else "p")

    def row(self) -> dict:
        r = {"start": hex(self.start), "end": hex(self.end), "perms": self.perms,
             "pgoff": hex(self.pgoff << 12) if self.file else "0",
             "size_kb": (self.end - self.start) // 1024,
             "path": self.path or self.kind, "via": self.path_via,
             "stale": self.stale_reason or ""}
        if self.resident is not None:
            r["in_dump"] = self.resident.get("ok", 0)
            r["pages"] = sum(self.resident.values())
        return r


class VmaFinder:
    def __init__(self, k: Kernel):
        self.k = k
        b = k.btf
        self.off_mm = b.offset("vm_area_struct", "vm_mm")
        self.limit = TASK_SIZE_MAX_LA57 if k.img.la57 else TASK_SIZE_MAX
        self.liveness = None
        if b.has_field("vm_area_struct", "detached"):
            self.liveness = "detached"
        elif b.has_field("vm_area_struct", "vm_refcnt"):
            self.liveness = "vm_refcnt"
        self.linked = b.has_field("mm_struct", "mmap") and b.has_field("vm_area_struct", "vm_next")

    def _read(self, va: int, mm_va: int, found_by: str) -> Vma | None:
        k = self.k
        v = k.obj("vm_area_struct", va)
        if not v or v.ptr("vm_mm") != mm_va:
            return None
        s, e = v.int("vm_start"), v.int("vm_end")
        if s is None or e is None or not (0 <= s < e <= self.limit) or s & 0xFFF or e & 0xFFF:
            return None
        # A vm_area_struct is a slab object of its own, so it starts on a slot
        # boundary. Other structures carry (start, end, mm) at the same offsets
        # (vm_area_desc and friends, often inside kmalloc objects), and on 7.1.5
        # one such object 96 bytes into a foreign kmalloc-cg-192 slot read as a
        # live VMA from 0 to the stack: it overlapped every real VMA of the
        # process and pushed all of them out (v71c). The slab map knows the
        # slot geometry of every captured slab page; the cache name is not
        # used, because merged caches report another cache's name.
        sm = k.img.slabmap
        base = sm.slot_start(va) if sm is not None else None
        if base is not None and base != va:
            return None
        flags = v.int("vm_flags") or 0
        if flags >> 62:
            return None
        vma = Vma(va=va, start=s, end=e, flags=flags, pgoff=v.int("vm_pgoff") or 0,
                  file=v.ptr("vm_file") or 0, found_by=found_by)
        if self.liveness == "detached" and v.int("detached"):
            vma.stale, vma.stale_reason = True, "detached"
        elif self.liveness == "vm_refcnt":
            rc = v.int("vm_refcnt")
            if rc == 0:
                vma.stale, vma.stale_reason = True, "refcnt=0"
        if vma.file:
            if is_kptr(vma.file):
                fp = ko.file_path(k, vma.file)
                if fp and fp["path"] == ko.BROKEN + "/":
                    fp = None          # struct file captured, no name reachable
                if fp:
                    vma.path, vma.path_complete, vma.deleted = fp["path"], fp["complete"], fp["deleted"]
                    vma.path_via = "file"
                    if vma.deleted:
                        vma.path += " (deleted)"
                else:
                    # The struct file was charged elsewhere. On overlayfs from
                    # 6.6 it is the backing file, kzalloc'd without accounting.
                    # The pointer still groups the VMAs of one file together.
                    vma.path = f"<file {vma.file:#x} not captured>"
            else:
                return None
        return vma

    def find(self, mm_va: int) -> list[Vma]:
        k = self.k
        found: dict[int, Vma] = {}
        pat = mm_va.to_bytes(8, "little")
        for pa in k.phys.find_all(pat, align=8):
            va = k.dmap.va(pa) - self.off_mm
            if va in found:
                continue
            v = self._read(va, mm_va, "anchor")
            if v:
                found[va] = v
        if self.linked:
            mm = k.obj("mm_struct", mm_va)
            nxt = mm.ptr("mmap") if mm else None
            hops = 0
            while is_kptr(nxt) and hops < 65536:
                hops += 1
                if nxt in found:
                    found[nxt].found_by = "list+anchor"
                    nxt = k.obj("vm_area_struct", nxt).ptr("vm_next")
                    continue
                v = self._read(nxt, mm_va, "list")
                if not v:
                    break
                found[nxt] = v
                nxt = k.obj("vm_area_struct", nxt).ptr("vm_next")
        vmas = sorted(found.values(), key=lambda x: (x.start, x.stale, x.end))
        self._mark_overlaps(vmas)
        self._label(mm_va, vmas)
        self._pagecache_paths(mm_va, vmas)
        return vmas

    def _pagecache_paths(self, mm_va: int, vmas: list[Vma]) -> None:
        """Name files whose struct file is not in the dump, from their pages."""
        pending = [v for v in vmas if v.file and v.path_via != "file" and not v.stale]
        if not pending or self.k.img.pagemeta is None:
            return
        from .pagecache import PageCache
        if not hasattr(self, "_pc"):
            self._pc = PageCache(self.k)
        mm = self.k.obj("mm_struct", mm_va)
        pgd = mm.ptr("pgd") if mm else None
        a = self.k.address_space(pgd) if pgd else None
        if a is None or not a.pgd_present:
            return
        # all VMAs of one struct file map the same inode: resolve once per file
        by_file: dict[int, dict | None] = {}
        for v in pending:
            if v.file not in by_file or by_file[v.file] is None:
                by_file[v.file] = self._pc.vma_file(a, v.start, v.end)
        for v in pending:
            hit = by_file.get(v.file)
            if hit:
                v.path, v.path_complete, v.path_via = hit["path"], hit["complete"], "pagecache"

    @staticmethod
    def _mark_overlaps(vmas: list[Vma]) -> None:
        """Two live VMAs cannot overlap: resolve every overlap, remnant first.

        The VMA that overlaps the most others goes first. A remnant spanning a
        whole address space overlaps every real VMA, and deciding pairwise in
        address order let it win against each of them in turn. Ties keep the
        pairwise rule: a VMA reached by walking the list beats one found only
        by its vm_mm anchor, and otherwise the later start loses.
        """
        live = [v for v in vmas if not v.stale]
        while True:
            count = {id(v): 0 for v in live}
            for i, v in enumerate(live):
                for w in live[i + 1:]:
                    if w.start >= v.end:
                        break
                    count[id(v)] += 1
                    count[id(w)] += 1
            worst = max(count.values(), default=0)
            if worst == 0:
                return
            loser = max((v for v in live if count[id(v)] == worst),
                        key=lambda v: (v.found_by == "anchor", v.start))
            loser.stale, loser.stale_reason = True, "overlaps-live"
            live = [v for v in live if v is not loser]

    def _label(self, mm_va: int, vmas: list[Vma]) -> None:
        mm = self.k.obj("mm_struct", mm_va)
        if not mm:
            return
        brk0 = mm.int("start_brk")
        stack = mm.int("start_stack")
        vdso = mm.ptr("context.vdso") if mm.has("context.vdso") else None
        for v in vmas:
            if v.file:
                continue
            if vdso and v.start == vdso:
                v.kind = "[vdso]"
            elif vdso and v.end == vdso and v.flags & VM_READ and not v.flags & VM_WRITE:
                v.kind = "[vvar]"
            elif brk0 is not None and v.start <= brk0 < v.end:
                v.kind = "[heap]"
            elif stack and v.start <= stack < v.end:
                v.kind = "[stack]"
            elif v.flags & VM_GROWSDOWN:
                v.kind = "[stack?]"
