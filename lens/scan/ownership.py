"""Which of the recovered tasks belong to the captured container?

A slab page is captured whole when at least one object on it is charged to the
target, so its neighbours come along: tasks of other containers, of the host,
kernel threads, and remnants of processes that already exited. They are real
objects, correctly parsed, and not the container's. Listing them as the
container's processes would be an attribution error; hiding them would throw
away evidence (a `runc` or `containerd-shim` remnant beside the target is
itself informative). So every task gets an ownership verdict and the basis for
it, and the report shows both.

Evidence, strongest first:

  objcg        v2 capture: slabs.json records, per object, whether its objcg
               resolved to the target at capture time. Definitive.
  pslist       the capture-time process list names this task_struct. Definitive.
  pagetables   mm->pgd is in the dump. Page tables are kmem pages charged to the
               memcg of the process that faulted them, and cglime captures kmem
               pages of the target only (G11). A foreign process's pgd is never
               captured. Available on captures that include kmem pages.
  thread-group same mm (or same tgid) as a task already judged owned.
  pidns        same innermost pid namespace as an owned task (not the init
               namespace): another process of the same container, even when its
               own mm was not captured.
  vma-completeness
               the share of the process's VMAs that are in the dump, against
               mm->map_count. VMAs are accounted objects charged to the memcg of
               the process that created them, so an owned process has close to
               all of them captured. A neighbour has only those that happen to
               share a slab page with the target's: on the 5.15 CRM capture,
               host containerd had 20 of its VMAs in the dump, the target 404 of
               404. A raw count cannot separate those; a ratio can.

Negative evidence:

  kthread      kernel threads are never charged to a container.
  objcg-foreign  v2 capture says the object slot belongs to another cgroup.
"""
from __future__ import annotations

from ..core.kernel import Kernel
from .tasks import Task

OWNED = "owned"
LIKELY = "likely-owned"
FOREIGN = "co-resident"
UNKNOWN = "unknown"

VMA_COMPLETE = 0.8   # share of mm->map_count present to call a process likely owned


class Ownership:
    def __init__(self, k: Kernel, vma_counter=None):
        self.k = k
        img = k.img
        self.vma_counter = vma_counter
        self.slabmap = img.slabmap
        self.pslist_vas: set[int] = set()
        cp = img.capture_pslist or {}
        for p in cp.get("processes") or []:
            try:
                self.pslist_vas.add(int(p["task_virt"], 16))
            except (KeyError, ValueError, TypeError):
                pass
        self.capture_has_kmem: bool | None = img.has_pagetables_hint

    def judge(self, tasks: list[Task]) -> None:
        k = self.k
        pgd_seen_any = False
        for t in tasks:
            ev = t.evidence
            if t.flags & 0x00200000:
                ev["kthread"] = True
            if self.slabmap is not None:
                own = self.slabmap.owned(t.va)
                if own is not None:
                    ev["objcg"] = own
            if t.va in self.pslist_vas:
                ev["pslist"] = True
            if t.mm:
                mm = k.obj("mm_struct", t.mm)
                ev["mm_in_dump"] = mm.present
                if mm:
                    pgd = mm.ptr("pgd")
                    has = bool(pgd) and k.dmap.present(pgd)
                    ev["pagetables"] = has
                    pgd_seen_any |= has
        # Without kmem pages in the capture, a missing pgd says nothing.
        pgd_meaningful = self.capture_has_kmem or pgd_seen_any

        owned_mms: set[int] = set()
        owned_tgids: set[int] = set()
        for t in tasks:
            ev = t.evidence
            if ev.get("objcg") is True:
                t.ownership, t.ownership_basis = OWNED, "objcg"
            elif ev.get("pslist"):
                t.ownership, t.ownership_basis = OWNED, "capture-pslist"
            elif ev.get("objcg") is False:
                t.ownership, t.ownership_basis = FOREIGN, "objcg-foreign"
            elif ev.get("kthread"):
                t.ownership, t.ownership_basis = FOREIGN, "kthread"
            elif ev.get("pagetables"):
                t.ownership, t.ownership_basis = OWNED, "pagetables"
            if t.ownership == OWNED:
                if t.mm:
                    owned_mms.add(t.mm)
                owned_tgids.add(t.tgid)

        for t in tasks:
            if t.ownership != UNKNOWN:
                continue
            ev = t.evidence
            if (t.mm and t.mm in owned_mms) or t.tgid in owned_tgids:
                t.ownership, t.ownership_basis = OWNED, "thread-group"
                continue
            nvma = total = ratio = None
            if t.mm and ev.get("mm_in_dump") and self.vma_counter:
                nvma = self.vma_counter(t.mm)
                total = k.obj("mm_struct", t.mm).int("map_count")
                ev["vmas_in_dump"], ev["map_count"] = nvma, total
                if total and total > 0:
                    ratio = nvma / total
            vtag = f"vmas={nvma}/{total}" if nvma is not None else ""
            if pgd_meaningful and t.mm and ev.get("mm_in_dump") and not ev.get("pagetables"):
                t.ownership, t.ownership_basis = FOREIGN, "no-pagetables"
            elif ratio is not None and ratio >= VMA_COMPLETE:
                t.ownership, t.ownership_basis = LIKELY, vtag
            elif t.mm and not ev.get("mm_in_dump"):
                # An owned process's mm_struct is charged to the container and
                # captured -- on a capture that includes kmem pages. On older
                # captures slab attribution itself was incomplete, so a missing
                # mm is not evidence of anything.
                t.ownership, t.ownership_basis = (FOREIGN if pgd_meaningful else UNKNOWN,
                                                  "mm-not-captured")
            elif t.lifecycle in ("released", "exiting", "zombie") and not t.mm:
                t.ownership, t.ownership_basis = UNKNOWN, "exited-no-mm"
            else:
                t.ownership, t.ownership_basis = FOREIGN, vtag or "weak"

        # Second pass: the pid namespace of anything owned pulls in the rest of
        # that container (a thread whose leader's mm is gone, a sibling process).
        owned_ns = {t.pidns for t in tasks if t.ownership in (OWNED, LIKELY) and t.pidns}
        for t in tasks:
            if t.ownership in (UNKNOWN, FOREIGN) and t.pidns in owned_ns \
                    and t.ownership_basis not in ("kthread", "objcg-foreign"):
                t.ownership, t.ownership_basis = LIKELY, "pidns"
