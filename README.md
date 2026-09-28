# cglens

Offline analysis of [cglime](https://github.com/jonscafe/cglime) container memory captures.

A cglime dump holds only the pages charged to one container. It has no
`init_task`, no kernel image and no kernel page tables, so Volatility's Linux
plugins open it and find nothing. cglens works from the objects that ARE in
the dump (slab objects, the container's own page tables, its user pages) and
from kernel metadata that a v2 capture records beside the dump.

```bash
python3 cglens.py info     capture.cglime
python3 cglens.py pslist   capture.cglime
python3 cglens.py maps     capture.cglime -p 1234
python3 cglens.py files    capture.cglime
python3 cglens.py filedump capture.cglime --path /tmp/payload -D out/
python3 cglens.py malfind  capture.cglime
python3 cglens.py grep     capture.cglime -s "Authorization: Bearer"
```

No dependencies, Python 3.10+, nothing to install. `--json` on every plugin.

---

## Plugins

| Plugin | What it recovers | vol3 counterpart | Needs |
|---|---|---|---|
| `info` | capture format, kernel, constants, which analyses this capture supports | `banners`/`info` | manifest |
| `psscan` | every `task_struct` in the dump, including co-resident, exited and kernel threads, with an ownership verdict | `linux.psscan` | BTF, `page_offset_base`, slab pages |
| `pslist` | container processes (owned tasks), per process or `--threads` | `linux.pslist` | same |
| `pstree` | parent/child tree inside the container | `linux.pstree` | same |
| `maps` | VMAs per process, residency in the dump, file names | `linux.proc.Maps` | same; residency needs page tables |
| `cmdline` | argv, read through the process's own page tables | `linux.psaux` | page tables (kmem pages) |
| `envars` | initial environment block | `linux.envars` | page tables |
| `lsof` | open fds: files, deleted files, memfds, sockets, pipes | `linux.lsof` | slab pages |
| `sockstat` | sockets per fd: inet/inet6 addresses, ports, TCP state, unix paths; `--scan` also sweeps socket caches for sockets without an fd | `linux.sockstat` | slab pages; `--scan` needs v2 |
| `procdump` | per VMA memory files plus a hole map saying why each hole exists | `linux.proc.Maps --dump` | page tables |
| `vaddump` | the same, by vol3's name; `--address` picks the VMA holding an address | `linux.proc.Maps --dump` | page tables |
| `elfs` | ELF headers at the start of mappings (file, memfd, anonymous); `-D` rebuilds each from its PT_LOAD segments. Loaded objects whose header page is not in the dump are listed by name with header `not captured` (`--header-only` hides them) | `linux.elfs` | page tables |
| `malfind` | executable memory not backed by a file on disk: anonymous, write+exec, memfd, deleted, with a hexdump | `linux.malfind` | VMAs; preview needs page tables |
| `files` | every inode in the dump (open, mapped, or only cached), its page cache size and how much was captured | `linux.pagecache.Files` | slab pages |
| `filedump` | files rebuilt from captured page cache, with sha256 when complete and a per-page gap map | `linux.pagecache.InodePages --dump` | `vmemmap_base`; XArray nodes or v2 pagemeta |
| `grep` | string / hex / regex search; each hit attributed to a process address, a file offset, or a kernel object | `yarascan` (without YARA) | page tables for process attribution |

A PID given to `-p` may be the init namespace PID, any intermediate namespace
PID, or the PID inside the container.

---

## How it finds things without init_task

**Tasks: self-referential list heads.** An empty `list_head` points at itself.
Knowing `page_offset_base`, the virtual address of every byte in the dump is
known, so "this qword equals its own address" can be tested at every 64 byte
slot without knowing where objects start. `task_struct` has several heads that
are empty for almost every task (`ptraced`, `ptrace_entry`, `perf_event_list`,
`children` for leaves); two together, then field checks (pid range, printable
`comm`, `group_leader == self` for leaders), leave no false positives on the
captures tested.

**VMAs: pointer-anchored search.** From 6.1 the VMA tree's nodes are not memcg
accounted and are not in the dump; `vm_area_struct` objects are. The eight
bytes of an `mm_struct` address are searched for across the dump at C speed,
and every hit at the `vm_mm` offset is a candidate VMA. Freed VMAs are kept and
marked stale by the kernel's own liveness field (`detached`, `vm_refcnt`) or
by overlap.

**User memory: the container's own page tables.** They are kmem pages charged
to the container, captured by cglime from the G11 fix onwards. `mm->pgd` gives
the root; the walk reports each hole as page-not-captured,
pagetable-not-captured, pte-not-present or swap entry.

**File names: a cascade.** `vm_file` first. On overlayfs from 6.6 that struct
file is an unaccounted backing file, so then: `struct page.mapping` of a
captured page cache page to its inode and dentry (v2 captures); `mm->exe_file`
for the executable, or when its dentry is not in the dump, the path the
process was exec'd with (`AT_EXECFN` from `mm->saved_auxv`, read off the
captured stack; for a `#!` script, the interpreter binfmt_script put in
`argv[0]`); the process's own dynamic linker `link_map` list, which lives in
captured writable memory; and `AT_BASE` for the program interpreter. Every
name says which route it came by (`via`).

**Inodes and page cache.** An inode's `i_mapping` points at its own embedded
`i_data`, and `i_data.host` points back at the inode. The self-relative search
(`scan/selfptr.py`) finds every qword that points a fixed distance from itself
at C speed, so all inodes in the dump are found in well under a second. Each
inode's `i_pages` XArray maps file offsets to folios; a folio pointer minus
`vmemmap_base` gives the PFN, and the page is in the dump if it was charged to
the container. A v2 capture's `pagemeta.bin` indexes the same pages from the
other side (`struct page.mapping` and `index`), and `filedump` reports where
the two disagree. Files the container wrote and closed, or wrote and deleted
while holding them open, are recovered this way.

---

## Ownership

A slab page is captured whole when any object on it belongs to the target.
Where a cache holds several objects per slab (task_struct on 7.1, dentries,
files), the other objects on that page come along too: host daemons, other
containers, kernel threads, and exited processes.
On captures taken before cglime's G16/G17 fix, many more foreign objects are
present. Out-of-range objcg reads caused whole slab pages to be captured by
mistake. cglens discards those indices when it reads the ownership map and
reports how many slabs were affected (`info`, `slab_map_repairs`). cglens reports them all and judges each one, strongest
evidence first:

| Basis | Meaning |
|---|---|
| `objcg` | v2 capture: the object's `obj_cgroup` resolved to the target at capture time. Definitive |
| `capture-pslist` | named by the process list cglime recorded at capture time. Definitive |
| `pagetables` | `mm->pgd` is in the dump. Page tables are charged to the owning container and only the target's are captured |
| `thread-group` / `pidns` | shares an mm, TGID or innermost pid namespace with an owned task |
| `vmas=N/M` | N of the process's M VMAs (`mm->map_count`) are in the dump. Owned processes are near 100%; neighbours are not (CRM capture: target 404/404, host containerd 20/94) |
| `kthread`, `objcg-foreign`, `no-pagetables` | positively not the container's |

`psscan` shows everything; `pslist` shows owned and likely-owned tasks.

---

## Captures it reads

| Capture | What works |
|---|---|
| cglime v2 (`scan` with sidecars, then `bundle create`) | everything; BTF comes from the capture, ownership is definitive |
| cglime `scan` after the G11 fix, no sidecars | everything, with `--btf` for the captured kernel; ownership by page tables |
| older `scan` dumps (before G11) | tasks, VMAs, lsof; no user memory (no page tables in the dump) |
| `acquire` (userspace path) | none of the kernel object analyses: no slab pages, no `page_offset_base` |

For a capture without embedded BTF, pass the BTF of the captured kernel with
`--btf` or put `<kernel_release>.btf` files in a directory and pass
`--btf-dir`. That is the analyst's claim that it matches, and every report says
so. `--no-sidecars` analyses a v2 capture as if it were older, for comparison.

---

## Validation

`testing/cglens_live.py` in the research workspace starts a known workload,
freezes it, reads ground truth from `/proc`, captures it with cglime v2,
removes the container, then compares cglens output against the ground truth.
On WSL2 6.6.87.2 (2026-09-28), 30 of 30 checks pass, covering:

- threads, namespaced PIDs, ppid, cmdline and environment, exactly
- VMA ranges and permissions, exactly
- open fds and file names
- sha256 of a file the container wrote and closed, a file it deleted while
  holding it open, and a shared object loaded from a memfd, all rebuilt from
  page cache
- sockets (TCP listen and established, UDP, unix path)
- malfind on an anonymous rwx region and on the memfd-loaded library
- `elfs` rebuilding that library, with read-only segments byte-identical to
  the original
- `vaddump --address`
- `grep` attributing a heap marker to the process and a file marker to the
  file

The same dump analysed without sidecars reaches the same thread list through
page-table ownership.

On the 7.1.5 VM the same harness passed 28 of 30 at first. The failures traced
to cglime, not cglens (`docs/DESIGN.md` E84; cglime FAILURES G16, G17):

- On 7.x, `struct file` slabs keep each object's objcg entry inside the object
  (stride 192), but the scanner read them at 8-byte steps.
- The scanner also read a fixed 64 entries whatever the slab held.

With both fixed in the scanner, the harness passes 30 of 30 on 7.1.5 and on
6.6. The fix also removed over-capture: 240 of 661 slabs in the earlier 7.1.5
capture had been captured by mistake.

Re-run for release on fresh captures from both hosts, with one more
(informational) check that the target was not reclaimed before capture: 31 of
31 on WSL2 6.6 and 31 of 31 on 7.1.5. On the way it found a VMA remnant that
hid every mapping of a process and a pipe reported as a path; both are fixed
and described in `docs/DESIGN.md`.

---

## Sample capture

A redacted capture of a synthetic workload is attached to the GitHub release,
with everything planted in it listed in [`samples/README.md`](samples/README.md):
threads, a child process, open, deleted and closed files, memfds including a
fileless library, an RWX page, sockets and heap markers. The scripts that made
it are in `samples/`, including the redaction and the checks it passed.

Task discovery and `files`/`filedump` were also run on existing captures from
all three memcg eras (5.15, 6.6, 7.1); see `docs/DESIGN.md`.

---

## Limits

- x86_64 only. 5-level paging is handled from `kernel.json` but untested.
- The path of a file is relative to its own filesystem root, and breaks with
  a marker where a parent dentry was not captured.
- A struct file whose dentry and inode are both outside the dump has no name:
  `lsof` says `<struct file captured, name not reachable>`. Typical for the
  stdout and stderr pipes containerd-shim creates.
- `link_map` names are userspace data: what the process believed it loaded.
- Abstract unix socket names live in an unaccounted allocation and are usually
  not in the dump; the socket is reported as bound without its name.
- Page cache that another cgroup populated first (shared image layers) is not
  the container's and is not in the dump: `filedump` reports those pages as
  not captured.
- No YARA engine (zero dependency); `grep` covers strings, hex and regex.

## License

Apache License 2.0.
