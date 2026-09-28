"""One analysis session over one capture: shared, lazily computed state."""
from __future__ import annotations

from .core.image import Image
from .core.kernel import Kernel
from .core.layers import AddressSpace
from .scan.ownership import FOREIGN, LIKELY, OWNED, Ownership
from .scan.tasks import Task, TaskScanner
from .scan.vmas import Vma, VmaFinder


class Session:
    def __init__(self, img: Image, stride: int = 64):
        self.img = img
        self.stride = stride
        self._k: Kernel | None = None
        self._tasks: list[Task] | None = None
        self._vmas: dict[int, list[Vma]] = {}
        self._vf: VmaFinder | None = None
        self.scan_stats: dict = {}
        self.naming_stats: dict[int, dict] = {}
        self._inodes = None
        self.inode_stats: dict = {}

    @property
    def k(self) -> Kernel:
        if self._k is None:
            self._k = Kernel(self.img)
        return self._k

    @property
    def vma_finder(self) -> VmaFinder:
        if self._vf is None:
            self._vf = VmaFinder(self.k)
        return self._vf

    def vmas(self, mm_va: int) -> list[Vma]:
        if mm_va not in self._vmas:
            vmas = self.vma_finder.find(mm_va)
            # Files the kernel's own records cannot name (struct file and page
            # cache charged elsewhere): try mm->exe_file, then the process's
            # dynamic linker state.
            if any(v.file and not v.path_via for v in vmas):
                from .scan import linkmap
                mm = self.k.obj("mm_struct", mm_va)
                pgd = mm.ptr("pgd") if mm else None
                a = self.k.address_space(pgd) if pgd else None
                a = a if a is not None and a.pgd_present else None
                self.naming_stats[mm_va] = linkmap.name_vmas(self.k, a, mm_va, vmas)
            self._vmas[mm_va] = vmas
        return self._vmas[mm_va]

    def tasks(self) -> list[Task]:
        if self._tasks is None:
            sc = TaskScanner(self.k, stride=self.stride)
            tasks = sc.scan()
            Ownership(self.k, vma_counter=lambda mm: sum(
                1 for v in self.vmas(mm) if not v.stale)).judge(tasks)
            self.scan_stats = sc.stats
            self._tasks = tasks
        return self._tasks

    def owned(self, include_likely: bool = True) -> list[Task]:
        ok = {OWNED, LIKELY} if include_likely else {OWNED}
        return [t for t in self.tasks() if t.ownership in ok]

    def foreign(self) -> list[Task]:
        return [t for t in self.tasks() if t.ownership == FOREIGN]

    def processes(self, tasks: list[Task] | None = None) -> list[Task]:
        """One representative per thread group: the leader if recovered."""
        tasks = self.owned() if tasks is None else tasks
        groups: dict[int, list[Task]] = {}
        for t in tasks:
            groups.setdefault(t.tgid, []).append(t)
        out = []
        for tgid, ts in sorted(groups.items()):
            lead = next((t for t in ts if t.pid == tgid), None)
            rep = lead or next((t for t in ts if t.mm), ts[0])
            rep._threads = ts  # type: ignore[attr-defined]
            out.append(rep)
        return out

    def select(self, pids: list[int] | None, all_tasks: bool = False) -> list[Task]:
        base = self.tasks() if all_tasks else self.owned()
        procs = self.processes(base)
        if not pids:
            return procs
        want = set(pids)
        # a PID from any namespace level selects the process: init-namespace,
        # an intermediate runtime namespace, or the container's own
        return [t for t in procs if t.tgid in want or t.pid in want
                or want.intersection(t.ns_chain or ())]

    def aspace(self, t: Task) -> AddressSpace | None:
        if not t.mm:
            return None
        mm = self.k.obj("mm_struct", t.mm)
        if not mm:
            return None
        pgd = mm.ptr("pgd")
        a = self.k.address_space(pgd) if pgd else None
        return a if a and a.pgd_present else None

    def inodes(self):
        """Every inode in the dump (self-relative scan), cached."""
        if self._inodes is None:
            from .scan.inodes import InodeScanner
            sc = InodeScanner(self.k)
            self._inodes = sc.scan()
            self.inode_stats = sc.stats
        return self._inodes
