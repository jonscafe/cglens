# cglens design

Status: MVP plus vol3-parity plugins, 2026-09-28. Written in English per the project convention.

## 1. Problem

cglime scopes acquisition to one memory cgroup. The dump is correct LiME with
real physical addresses, but a sparse subset: no kernel image, no `init_task`,
no kernel page tables, no vmemmap. Every existing Linux memory framework starts
from the kernel's own entry points (banner, symbols, `init_task`, the kernel
DTB) and has nowhere to start. cglime's README listed "Offline analysis: none";
`pslist`, `slab`, `calibrate` and `kpagecg` all read a live kernel.

cglens is the offline side: it analyses the dump after the container, and the
host, are gone.

## 2. What the research already established, and what follows from it

| cglime finding | Consequence for cglens |
|---|---|
| Slab pages are captured whole when any object is the target's (object level attribution, E30s) | The dump holds the target's `task_struct`, `mm_struct`, `vm_area_struct`, `file`, `dentry`, `inode`, `pid` objects, and their neighbours'. Discovery must scan, and ownership must be judged per object |
| kmem pages (page tables) are captured from G11 (E72) | The container's own page tables are in the dump: user memory is readable through `mm->pgd`, no kernel page table needed |
| `page_offset_base`, `vmemmap_base` are recorded in the scan manifest | Every slab object's virtual address is `page_offset_base + pa`: pointer following works in the direct map |
| `task_struct.pid` is the init namespace PID (K6) | Report the whole `struct pid` chain; select by any level |
| Compound folios (G4, G10) | Objects can straddle a missing page: typed reads are partial-aware |
| Three memcg eras, layouts move (struct slab split, `compound_info` in 7.x, `d_alias` leaving `d_u`) | All layout comes from BTF of the captured kernel; field lookups have fallbacks, never version checks |
| Metadata that exists only live (`scan --pslist`) must be captured then | v2 sidecars (section 5) |

## 3. Architecture

```
cglens.py                 CLI: <plugin> <capture> [--btf|--btf-dir] [--json]
lens/core/image.py        open .cglime (zip) or .lime + sidecars; BTF resolution order
lens/core/layers.py       PhysicalLayer (mmap, sparse) -> DirectMap -> AddressSpace (4/5 level)
lens/core/btf.py          full BTF type graph, dotted member paths through anonymous unions
lens/core/kernel.py       Obj: typed, partial-aware struct views
lens/core/objects.py      task state/lifecycle, ns pid chain, pidns, creds, dentry paths, files
lens/core/pagemeta.py     reader for pagemeta.bin (struct page per captured PFN)
lens/scan/tasks.py        task discovery by self-referential list_head signature
lens/scan/vmas.py         VMA discovery by pointer-anchored search, liveness, labels
lens/scan/ownership.py    ownership verdict and basis per task
lens/scan/pagecache.py    page -> mapping -> inode -> dentry
lens/scan/linkmap.py      file names from the process's link_map list
lens/scan/selfptr.py      self-relative pointer search (any delta), C-speed
lens/scan/inodes.py       inode discovery, XArray page cache walk, pagemeta index
lens/scan/elf.py          ELF header parsing and PT_LOAD rebuild
lens/scan/rmap.py         physical page -> process address / file offset / kernel object
lens/core/slabmap.py      v2 per-object ownership by address containment
lens/plugins/*.py         info psscan pslist pstree maps cmdline envars lsof sockstat
                          procdump vaddump elfs malfind files filedump grep
```

Every read that can fail says why. A hole in process memory is one of
`page-not-captured`, `pagetable-not-captured`, `pte-not-present`,
`pte-swap-entry`: an acquisition gap and a property of the process are
different findings.

## 4. Techniques

**4.1 Self-referential list heads (tasks).** `INIT_LIST_HEAD(h)` stores `&h`
in `h->next`. With the direct map base known, the address of any qword in the
dump is computable, so the test runs over strided `memoryview` casts at C-ish
speed without knowing object boundaries. Two of {`ptraced`, `ptrace_entry`,
`perf_event_list`, `children`, `cg_list`, `pi_state_list`} must hold. Candidates
that other structures produce by layout coincidence are rejected by field
checks; on the captures tested, all remaining hits were real tasks.

**4.2 Pointer-anchored search (VMAs).** Children point at parents. The mm's
address is searched as eight bytes over the whole dump; a hit at the `vm_mm`
offset is a candidate VMA, validated by range, alignment, a slab slot boundary
(when the slab map covers the page) and a round trip. The
maple tree (not accounted) is never needed. Pre-6.1 kernels also walk
`mm->mmap`, and each VMA records which method found it.

**4.3 Ownership.** Section "Ownership" in the README. The central addition over
cglime's live pslist is that offline evidence is graded, and the grade is
always printed.

**4.4 File naming cascade.** `vm_file` -> `struct page.mapping` (v2) ->
`mm->exe_file` -> `link_map`. Measured on the live capture below: 0 of 100
file-backed VMAs named by `vm_file` (6.6 overlay backing files are
kzalloc'd without accounting), 16 by page cache, 5 by `exe_file`, 65 by
`link_map`; 14 remained unnamed (ld.so itself and mmapped data files).

**4.5 Self-relative search (inodes, and a general primitive).** An empty
list head is the delta-0 case of a pointer whose value is its own address plus
a constant. `scan/selfptr.py` finds every such qword for any delta at C speed:
within one 64 KiB aligned region, all candidates share one of at most two
6-byte upper patterns, so `bytes.find` does the scanning and Python only checks
the few hits. Inodes are found with delta `offsetof(i_data) -
offsetof(i_mapping)` and confirmed by `i_data.host == inode`. The WSL2
capture's 787 inodes took 0.08 s.

**4.6 Page cache through the XArray.** `inode->i_data.i_pages` maps page index
to folio. Nodes come from `radix_tree_node` with `XA_FLAGS_ACCOUNT` on page
cache mappings, so the container's own are captured. Leaves are folio pointers
into the vmemmap (PFN = (ptr - vmemmap_base) / sizeof(struct page)); value
entries are shadows of evicted pages or shmem swap entries; sibling entries
extend a large folio. Every gap in a rebuilt file carries its reason. A v2
capture's pagemeta gives the same answer from the page side, and on the live
capture the two agreed on every page.

**4.7 ELF rebuild.** An ELF header at a mapping's start gives the program
headers; each PT_LOAD is read at load_bias + p_vaddr through the process page
tables and written at p_offset. Read-only segments come back byte-identical.
Writable ones hold relocated data, and pages never faulted in stay holes; both
are reported per segment.

**4.8 Reverse map (grep).** Walking the container's page tables gives
PFN -> (pid, va) and the VMA it falls in. Walking every inode's XArray gives
PFN -> (file, offset). v2 page classes and the slab map name kernel pages.
A hit is attributed by all of them that apply.

## 5. Sidecar format v2 (cglime side)

Written by `cglime/sidecar.py` from `memcg_scan.py --dump`, carried by
`bundle create`, all best effort (the dump never depends on them):

| File | Content | Why it cannot come later |
|---|---|---|
| `X.btf` | raw `/sys/kernel/btf/vmlinux` | types of the running kernel |
| `X.kernel.json` | `page_offset_base`, `vmemmap_base`, la57, constants in effect, memcg era, targets, kmem page count, selected kallsyms, BTF sha256 | KASLR values per boot |
| `X.pagemeta.bin` | raw `struct page` for every captured PFN plus the scanner's class (regular, kmem, slab, tail) | vmemmap is never in the dump |
| `X.slabs.json` | per captured slab folio: cache (name, size, objects), owned object indices | the objcg vector is never in the dump |

Measured cost on the live capture: 3,607 pagemeta records (288 KiB), 260 slab
folios in 52 caches, all named, 1.18 s added inside the freeze window.

## 6. Measurements

Codes: `E77` to `E84` number the experiments below, in the order they were
run; the research logs they come from are not published. `G`, `K` and the
other `E` codes are cglime's and are resolved in cglime's `FAILURES.md`.

**E77, task discovery on existing captures (no sidecars, analyst BTF).**

| Capture | Kernel / era | Tasks | Owned processes | Manifest | Basis |
|---|---|---|---|---|---|
| k8s_ctr | 6.6 direct | 6 | 1 | 1 | vmas 57/57 |
| k8s_pod | 6.6 direct | 7 | 2 | 2 | vmas 10/10, 57/57 |
| scan_crm | 5.15 page_mem_cgroup | 21 (8 threads target) | 1 | 1 | vmas 404/404 |
| thp_huge_fix | 7.1.5 objcg | 3 | 1 | 1 | vmas 91/91 |
| thp_huge_nofix | 7.1.5 objcg | 1 | 0 | 1 | the control arm drops slab tails, so the target task is not in the dump |
| fixed (early) | 6.6 | 29 | 0 judged | 1 | target visible (redis, nspid 1) but its mm was not captured by that early scanner: reported `unknown`, not owned |
| with_slab (early) | 6.6 | 0 | 0 | 1 | that scan attributed zero slab objects |

Each run took 0.4 to 0.8 s. Co-resident tasks seen include host `containerd`,
`dockerd`, `snapd`, other containers' processes, and released remnants of
`runc`, `containerd-shim`, `iptables` that exited before capture.

Correction (E84, K10 in cglime FAILURES): on 6.6 captures, where
`task_struct` has one object per slab, the co-resident tasks above were not
neighbours on a shared page. The slabs holding them were captured by mistake:
the scanner read objcg entries past the end of short vectors (G17). After the
scanner fix, a 6.6 capture of the same workload holds no foreign task at all.

**E78, VMA completeness as ownership.** On scan_crm the host's `containerd`
had its `mm_struct` and 20 of 94 VMAs in the dump; a count threshold called it
owned, the ratio does not. Target: 404 of 404.

**E79, live validation (WSL2 6.6.87.2, v2 capture, 2026-09-28).** 17 of 17:
exact thread list (5), processes (2), nspid, ppid inside the container,
cmdline, environment, VMA ranges and permissions for both processes, fd slots,
names of every captured file (deleted file, memfd, socket, pipes, /dev/null),
procdump markers from heap and a worker thread. stdout/stderr pipes are
created by containerd-shim and their struct files are not the container's:
reported as not captured, which is correct.

**E80, ablation.** The same dump without sidecars: identical thread list,
ownership basis `pagetables` instead of `objcg`.

**E81, vol3-parity plugins, live (WSL2 6.6, capture cgl3).** 30 of 30 checks.
These are the new ones:

- The closed file (3 pages + 123 bytes) was found through the inode scan
  alone; it had no fd or mapping. It was rebuilt with an exact sha256.
- The deleted-but-open file (9,000 bytes, nlink 0) matched its sha256.
- The memfd holding a shared object matched its sha256, and pagemeta agreed
  with the XArray on every page.
- Sockets matched the process's own `/proc/net` for TCP listen, both ends of
  an established pair, UDP, and a unix path socket. The unix path came from
  `unix_sock.path.dentry`, because `unix_address` is not accounted and was not
  in the dump.
- malfind flagged the anonymous rwx region and the memfd-loaded library.
- elfs rebuilt that library with its read-only segments identical to the
  original.
- `vaddump --address` returned exactly the rwx VMA.
- grep attributed the heap marker to the process and the file marker to
  `/tmp/cglens_known.bin`.

**E82, page cache on older captures.** 6.6 k8s_ctr (pre-v2, no page tables):
8 `.pyc` files the container compiled were rebuilt complete, with valid 3.12
magic. 7.1.5 thp_huge_fix: 12 files, including the workload's own JSON
(complete and parseable); its path exposes the containerd snapshot
(`.../snapshots/121/fs/tmp/...`). Six of the 7.1 files are missing exactly one
page each, `page-not-captured`, which matches G10 (large folio page[1] dropped
by that scanner version). The rebuild surfaces a known acquisition defect by
itself.

**E84, 7.1.5 validation and the scanner bug it found.** First run: 28 of 30.
Of the workload's 15 fds, 11 had no `struct file` in the dump. 3 of those
belonged to containerd-shim; the other 8 were the container's own.

The capture's pagemeta held the cause. The captured `filp`/`bfilp` slabs had
`struct slab.stride` = 192 / 256: an in-object slabobj_ext
(`_SLAB_OBJ_EXT_IN_OBJ`, present in the 7.1.5 BTF). Every owned index recorded
by the scanner was a multiple of 24 or 32, which is exactly what reading at
8-byte steps produces.

After the scanner fix (cglime `slabgeom.py`, G16/G17):

- 30 of 30 on 7.1.5 and 30 of 30 on 6.6.
- Slab pages captured fell from 661 to 487 on 7.1.5 and from 262 to 216 on
  6.6.
- Out-of-range owned indices went from 322 (7.1.5) and 34 (6.6) to 0.

cglens repairs older captures as far as the capture allows:

- In-object entries are re-read from the dump itself: 7 of 7 slabs in the old
  7.1.5 capture.
- Out-of-range indices are discarded: 46 slabs of the first 6.6 capture turn
  out to have been captured by mistake.

On 7.x, a mapped file's struct file is often an overlayfs backing file whose
own dentries belong to whoever first opened the file. Its `user_path` (the
path the container used) is read instead when that one resolves to a root.
This took file-backed VMA naming on the fixed 7.1.5 capture from 10 to 120 of
165.

**Release re-run, 2026-09-28 evening.** A fresh capture on each host after
the naming, elfs and freezer changes, and the cglime calibration fixes G19 and
G20 (without which the 6.6 host refused to capture at all):

- WSL2 6.6 (cgl6): 31 of 31, fresh and re-analysed.
- 7.1.5 (v71d): 30 of 31 fresh, 31 of 31 re-analysed after the lsof fix below.

The 7.1.5 runs found two cglens bugs and one environmental failure:

- **A VMA remnant that hid a whole process.** An object 96 bytes into a
  foreign `kmalloc-cg-192` slot carried (0, 0x7ffd6b6a7000, mm) at the
  offsets of `vm_start`, `vm_end`, `vm_mm`. It passed range and alignment,
  covered the whole address space, and overlap resolution in address order
  then marked every real VMA of `sleep` stale (v71c). A candidate VMA must now
  start on a slab slot boundary when the slab map knows the page, and overlaps
  are resolved worst first: the VMA overlapping the most others loses.
- **A pipe named "…/".** A containerd-shim pipe's struct file shared a
  captured slab page with the target's objects; its dentry and inode did not.
  `lsof` now says `<struct file captured, name not reachable>`, as `maps`
  already did.
- **The known file was evicted before capture** on the 1 GiB VM (v71c):
  memory.stat of a container started seconds earlier showed `pgsteal` 774.
  That is cglime's freeze gap (E73), not cglens. The harness now reports
  `target_not_reclaimed` as an informational check, and drops the page cache
  before starting the workload on that host.

**K9, ground truth PID level.** `docker run --pid=host` under Docker Desktop
is not the kernel's init namespace: the daemon runs one level down. Ground
truth PIDs (8977) matched level 1 of the recovered chain [11383, 8977, 1], not
`task_struct.pid`. The harness now matches on the chain level where they agree.

## 7. Roadmap

1. Validation of the new plugins on 7.1 and 5.15 hosts with v2 sidecars.
2. `bash`-style history recovery for shell processes.
3. Hermetic selftests for CI. Until then, `samples/redact.py` compares nine
   plugins on the raw and the redacted sample, which is a regression check on
   one known capture.
4. A Volatility 3 bridge (layer + ISF from BTF) once the object model settles.
5. JVM / Go / musl workloads (link_map naming assumes glibc).
