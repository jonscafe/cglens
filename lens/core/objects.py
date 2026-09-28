"""Readers for the kernel objects a container analysis follows.

Each reader tolerates absence. A dentry whose parent was charged to another
cgroup is not in the dump; the path is then reported with a marker where the
chain broke, rather than dropped or guessed.
"""
from __future__ import annotations

from .kernel import LIST_POISON2, Kernel, Obj, is_kptr

PF_EXITING = 0x00000004
PF_KTHREAD = 0x00200000

# task state bits (include/linux/sched.h), stable across 5.x - 7.x
TASK_INTERRUPTIBLE = 0x0001
TASK_UNINTERRUPTIBLE = 0x0002
TASK_STOPPED = 0x0004
TASK_TRACED = 0x0008
EXIT_DEAD = 0x0010
EXIT_ZOMBIE = 0x0020
TASK_PARKED = 0x0040
TASK_DEAD = 0x0080
TASK_FROZEN = 0x8000

BROKEN = "…"   # marks where a path chain left the dump


def task_state(t: Obj) -> str:
    """ps-style state letter plus qualifiers, from __state (or state) and exit_state."""
    st = t.int("__state") if t.has("__state") else t.int("state")
    ex = t.int("exit_state") or 0
    if ex & EXIT_ZOMBIE:
        return "Z"
    if ex & EXIT_DEAD:
        return "X"
    if st is None:
        return "?"
    letter = "R"
    if st & TASK_DEAD:
        letter = "X"
    elif st & TASK_TRACED:
        letter = "t"
    elif st & TASK_STOPPED:
        letter = "T"
    elif st & TASK_UNINTERRUPTIBLE:
        letter = "D"
    elif st & TASK_INTERRUPTIBLE:
        letter = "S"
    elif st & TASK_PARKED:
        letter = "P"
    if st & TASK_FROZEN:
        letter += "f"
    return letter


def task_lifecycle(t: Obj) -> str:
    """live | kthread | exiting | zombie | released

    `released` means release_task() already unlinked the task from the global
    list (tasks.prev poisoned): the object is a remnant of an exited process,
    kept only because the slab has not reused it yet.
    """
    flags = t.int("flags") or 0
    if flags & PF_KTHREAD:
        return "kthread"
    if t.has("tasks") and t.ptr("tasks.prev") == LIST_POISON2:
        return "released"
    ex = t.int("exit_state") or 0
    if ex & (EXIT_ZOMBIE | EXIT_DEAD):
        return "zombie" if ex & EXIT_ZOMBIE else "released"
    if flags & PF_EXITING:
        return "exiting"
    if not t.ptr("mm"):
        return "exiting"      # user task without an mm: exit_mm() has run
    return "live"


def task_ns_pids(k: Kernel, t: Obj) -> list[int] | None:
    """The task's PID at every pid-namespace level, outermost first.

    task_struct.pid is the init-namespace PID (K6 in cglime FAILURES.md). struct
    pid carries numbers[0..level], one per namespace the task is visible in:
    [init ns, ..., the container's own]. This is /proc/<pid>/status NSpid as
    seen from the init namespace. Nested runtimes add levels: on Docker Desktop
    the daemon's own namespace sits between the kernel's and the container's,
    so `docker run --pid=host` does NOT show init-namespace PIDs.
    """
    if not t.has("thread_pid"):
        return None
    pid = t.deref("thread_pid", "pid")
    if not pid:
        return None
    level = pid.int("level")
    if level is None or level > 32:
        return None
    base = pid.addr("numbers")
    usz = k.size("upid")
    nr_off = k.off("upid", "nr")
    raw = k.dmap.read(base, (level + 1) * usz)
    if raw is None:
        return None
    return [int.from_bytes(raw[i * usz + nr_off:i * usz + nr_off + 4], "little", signed=True)
            for i in range(level + 1)]


def task_pidns(k: Kernel, t: Obj) -> int | None:
    """Address of the innermost pid_namespace the task lives in.

    Tasks of one container share it (unless the runtime shares or nests PID
    namespaces), which groups threads and processes by container without any
    cgroup metadata.
    """
    if not t.has("thread_pid"):
        return None
    pid = t.deref("thread_pid", "pid")
    level = pid.int("level") if pid else None
    if level is None or level > 32:
        return None
    ns = k.dmap.u64(pid.addr("numbers") + level * k.size("upid") + k.off("upid", "ns"))
    return ns if is_kptr(ns) else None


def task_nspid(k: Kernel, t: Obj) -> tuple[int | None, int | None]:
    """(PID inside the task's innermost pid namespace, namespace level)."""
    chain = task_ns_pids(k, t)
    if not chain:
        return None, None
    return chain[-1], len(chain) - 1


def task_creds(k: Kernel, t: Obj) -> dict | None:
    c = t.deref("real_cred", "cred") if t.has("real_cred") else None
    if not c:
        return None
    out = {}
    for f in ("uid", "gid", "euid", "egid"):
        if c.has(f + ".val"):
            out[f] = c.int(f + ".val")
    return out


def dentry_name(k: Kernel, d: Obj) -> str | None:
    if not d:
        return None
    n = d.int("d_name.len")
    p = d.ptr("d_name.name")
    if n is None or not is_kptr(p) or n > 255:
        return None
    # Short names live inline (d_iname, d_shortname from 6.14); long ones in a
    # separately allocated external_name. Both are reached through the direct map.
    raw = b"" if n == 0 else k.dmap.read(p, n)
    if raw is None:
        return None
    return raw.decode("utf-8", "replace")


def dentry_unhashed(d: Obj) -> bool | None:
    """d_unhashed(): an unlinked (deleted) file keeps its dentry unhashed."""
    if not d or not d.has("d_hash"):
        return None
    pprev = d.ptr("d_hash.pprev")
    return pprev == 0


def dentry_path(k: Kernel, dentry_va: int | None, max_depth: int = 64) -> tuple[str, bool]:
    """Path from the dentry up to its superblock root.

    Returns (path, complete). A chain that leaves the dump is prefixed with the
    BROKEN marker and complete=False. The root reached is the root of the
    FILESYSTEM (for a container, usually its overlay root), not necessarily the
    process's view of '/'.
    """
    parts: list[str] = []
    va = dentry_va
    complete = True
    seen = set()
    for _ in range(max_depth):
        if not is_kptr(va) or va in seen:
            complete = False
            break
        seen.add(va)
        d = k.obj("dentry", va)
        if not d:
            complete = False
            break
        parent = d.ptr("d_parent")
        name = dentry_name(k, d)
        if parent == va:           # superblock root
            if name and name != "/" and not parts:
                parts.append(name)  # pseudo filesystems name their root
            break
        if name is None:
            complete = False
            break
        parts.append(name)
        va = parent
    else:
        complete = False
    path = "/" + "/".join(reversed(parts))
    if not complete:
        path = BROKEN + path
    return path, complete


def file_path(k: Kernel, file_va: int | None) -> dict | None:
    f = k.obj("file", file_va)
    if not f:
        return None
    dva = f.ptr("f_path.dentry")
    path, complete = dentry_path(k, dva)
    if not complete and k.has("backing_file", "user_path.dentry"):
        # 7.x overlayfs maps a "backing file": f_path is the real file on the
        # lower/upper layer, whose dentries were created by whoever first
        # looked the file up (often not this container), while user_path is
        # the overlay path the container used. Taken only when it resolves
        # all the way to a root, since for an ordinary struct file the same
        # offset is not a path at all.
        alt_d = k.dmap.u64(file_va + k.off("backing_file", "user_path.dentry"))
        if is_kptr(alt_d):
            alt, alt_ok = dentry_path(k, alt_d)
            if alt_ok and alt != "/":
                path, complete, dva = alt, True, alt_d
    d = k.obj("dentry", dva)
    deleted = dentry_unhashed(d) if d else None
    ino = None
    iva = f.ptr("f_inode") if f.has("f_inode") else None
    if is_kptr(iva):
        ino_obj = k.obj("inode", iva)
        if ino_obj:
            ino = ino_obj.int("i_ino")
    return {"path": path, "complete": complete, "deleted": bool(deleted),
            "inode": ino, "file": file_va}
