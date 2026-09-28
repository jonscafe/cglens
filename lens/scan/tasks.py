"""Find task_struct objects in a scoped dump, with no init_task and no list walk.

Volatility's pslist walks init_task->tasks. A cglime dump has neither
init_task nor most of the list, so that walk has nowhere to start. cglime's
live `pslist` solves this with the objcg vector and the slab cache name, both
of which are kernel metadata that is NOT in the dump.

Offline the signal has to come from the objects themselves. The one used here
is a self-referential empty list_head:

    INIT_LIST_HEAD(&p->ptraced)  ->  p->ptraced.next == &p->ptraced

An empty list_head holds its own virtual address. Knowing page_offset_base,
the virtual address of any byte in the dump is page_offset_base + its
physical address, so the check "this qword equals its own address" can be run
at every slot without knowing where any object starts. For a random qword the
chance of that is about 2^-64. task_struct has several such heads that are
empty for almost every task (ptraced, ptrace_entry, perf_event_list, and
children for a leaf or a thread), and requiring two of them together makes a
false positive a matter of layout coincidence, which the field checks below
then reject.

task_struct is allocated from a cache aligned to L1_CACHE_BYTES, and slabs
start on a page boundary, so objects start on 64 byte boundaries. The scan
uses that stride by default; --stride 8 exists for layouts that break it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.kernel import Kernel, Obj, is_kptr
from ..core import objects as ko

PID_MAX_LIMIT = 4 * 1024 * 1024
SELFREF_CANDIDATES = ("ptraced", "ptrace_entry", "perf_event_list", "children",
                      "cg_list", "pi_state_list")


@dataclass
class Task:
    va: int
    pa: int
    pid: int
    tgid: int
    comm: str
    mm: int
    flags: int
    lifecycle: str
    state: str
    selfref: list[str]
    group_leader: int = 0
    real_parent: int = 0
    nspid: int | None = None
    ns_level: int | None = None
    ns_chain: list[int] | None = None
    pidns: int | None = None
    start_ns: int | None = None
    creds: dict | None = None
    evidence: dict = field(default_factory=dict)
    ownership: str = "unknown"
    ownership_basis: str = ""
    ppid: int | None = None

    @property
    def is_leader(self) -> bool:
        return self.pid == self.tgid

    def row(self) -> dict:
        return {"pid": self.pid, "tgid": self.tgid, "nspid": self.nspid,
                "ppid": self.ppid, "comm": self.comm, "state": self.state,
                "ns_chain": self.ns_chain,
                "lifecycle": self.lifecycle, "ownership": self.ownership,
                "basis": self.ownership_basis,
                "uid": (self.creds or {}).get("uid"),
                "start_s": round(self.start_ns / 1e9, 3) if self.start_ns else None,
                "task": hex(self.va), "mm": hex(self.mm) if self.mm else "0"}


class TaskScanner:
    def __init__(self, k: Kernel, stride: int = 64, min_selfref: int = 2):
        self.k = k
        self.stride = stride
        self.min_selfref = min_selfref
        btf = k.btf
        self.size = k.size("task_struct")
        self.selfref = [(n, btf.offset("task_struct", n)) for n in SELFREF_CANDIDATES
                        if btf.has_field("task_struct", n)]
        if len(self.selfref) < min_selfref:
            raise RuntimeError("task_struct has too few list_heads for the signature")
        self.stats = {"slots_checked": 0, "signature_hits": 0, "rejected": 0,
                      "reject_reasons": {}}

    # ----------------------------------------------------------- discovery
    def candidates(self):
        """Physical addresses whose selfref heads hold their own address."""
        base = self.k.dmap.base
        offs = [o for _n, o in self.selfref]
        first_off = offs[0]
        stride_q = self.stride // 8
        for rpa, q in self.k.phys.qword_views():
            nq = len(q)
            # object start s must satisfy s % stride == 0 in physical terms;
            # ranges start page aligned so index 0 is aligned
            for start_q in range(0, nq, stride_q):
                self.stats["slots_checked"] += 1
                hits = 0
                qi = start_q + first_off // 8
                if qi < nq and q[qi] == base + rpa + qi * 8:
                    hits = 1
                    # full check only after the cheap first probe
                    for o in offs[1:]:
                        qj = start_q + o // 8
                        if qj < nq and q[qj] == base + rpa + qj * 8:
                            hits += 1
                else:
                    # the first head may be legitimately non-empty (a tracer):
                    # probe the second one before giving up
                    qj = start_q + offs[1] // 8
                    if not (qj < nq and q[qj] == base + rpa + qj * 8):
                        continue
                    for o in offs[1:]:
                        qj = start_q + o // 8
                        if qj < nq and q[qj] == base + rpa + qj * 8:
                            hits += 1
                if hits >= self.min_selfref:
                    self.stats["signature_hits"] += 1
                    yield rpa + start_q * 8

    def _reject(self, why: str) -> None:
        self.stats["rejected"] += 1
        r = self.stats["reject_reasons"]
        r[why] = r.get(why, 0) + 1

    def validate(self, pa: int) -> Task | None:
        k = self.k
        va = k.dmap.va(pa)
        t = k.obj("task_struct", va)
        if not t:
            self._reject("object-not-captured")
            return None
        if not t.complete:
            self.stats["partial_objects"] = self.stats.get("partial_objects", 0) + 1
        pid, tgid = t.int("pid"), t.int("tgid")
        if not (pid and tgid and 0 < pid < PID_MAX_LIMIT and 0 < tgid < PID_MAX_LIMIT):
            self._reject("pid-range")
            return None
        raw = t.bytes("comm")
        if raw is None:
            self._reject("comm-not-captured")
            return None
        nul = raw.find(b"\x00")
        if nul <= 0 or any(c < 0x20 or c > 0x7E for c in raw[:nul]):
            self._reject("comm")
            return None
        leader, rparent = t.ptr("group_leader"), t.ptr("real_parent")
        if not (is_kptr(leader) and is_kptr(rparent) and leader % 8 == 0):
            self._reject("pointers")
            return None
        if pid == tgid and leader != va:
            self._reject("leader-not-self")
            return None
        mm = t.ptr("mm") or 0
        if mm and not k.dmap.contains(mm):
            self._reject("mm-pointer")
            return None
        selfref = [n for n, o in self.selfref if t.u64_at(o) == va + o]
        task = Task(va=va, pa=pa, pid=pid, tgid=tgid, comm=raw[:nul].decode(),
                    mm=mm, flags=t.int("flags") or 0,
                    lifecycle=ko.task_lifecycle(t), state=ko.task_state(t),
                    selfref=selfref, group_leader=leader, real_parent=rparent)
        task.ns_chain = ko.task_ns_pids(k, t)
        task.pidns = ko.task_pidns(k, t) if task.ns_chain and len(task.ns_chain) > 1 else None
        if task.ns_chain:
            task.nspid, task.ns_level = task.ns_chain[-1], len(task.ns_chain) - 1
            if task.ns_chain[0] != pid:
                # numbers[0] must be the init-namespace PID, task_struct.pid
                task.evidence["ns_chain_mismatch"] = task.ns_chain
        task.creds = ko.task_creds(k, t)
        for f in ("start_time", "real_start_time"):
            if t.has(f):
                task.start_ns = t.int(f)
                break
        p = k.obj("task_struct", rparent)
        if p:
            task.ppid = p.int("tgid")
        return task

    def scan(self) -> list[Task]:
        seen: set[int] = set()
        out: list[Task] = []
        for pa in self.candidates():
            if pa in seen:
                continue
            seen.add(pa)
            t = self.validate(pa)
            if t:
                out.append(t)
        out.sort(key=lambda x: (x.tgid, x.pid, x.va))
        return out
