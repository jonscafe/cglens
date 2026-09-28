# Sample capture

`cglens-sample.cglime` is a real cglime v2 capture of a synthetic workload,
redacted for publication. It is attached to the GitHub release, not kept in
the repository, because a capture is 14 MB of binary.

| | |
|---|---|
| File | `cglens-sample.cglime`, 14,362,156 bytes |
| SHA-256 | `92cebedc33d23ca6c4b3d082cbb125f082137be643b2089f3ce06b8f47397cbb` |
| Workload | [`workload.py`](workload.py) in `python:3.12-slim`, frozen with `docker pause` |
| Kernel | 7.1.5-070105-generic, x86_64, objcg memcg era, on a throwaway lab VM |
| Captured by | cglime `scan --dump --pslist`, v2 sidecars, bundled |
| Redaction record | `redaction.json`, attached next to it |

```bash
python3 cglens.py info     cglens-sample.cglime
python3 cglens.py pstree   cglens-sample.cglime
python3 cglens.py envars   cglens-sample.cglime -p 1
python3 cglens.py sockstat cglens-sample.cglime
python3 cglens.py malfind  cglens-sample.cglime
python3 cglens.py filedump cglens-sample.cglime -D out --path cglens_
python3 cglens.py grep     cglens-sample.cglime -s CGLENS-SAMPLE-SECRET
```

## What is in it

Everything below was planted by `workload.py`, so there is a right answer to
check each plugin against.

- Two processes: `python3` (PID 1 in the container, three named worker
  threads) and its child `sleep 3600`.
- Environment `CGLENS_SECRET=CGLENS-SAMPLE-ENV` and `CGLENS_MODE=sample`. The
  "secret" is the marker string and nothing else.
- Open files: `/tmp/cglens_open.txt`, and `/tmp/cglens_deleted.txt`, unlinked
  while still held open.
- `/tmp/cglens_known.bin`, written and closed, so it is reachable only through
  its inode and page cache. `filedump` rebuilds it complete, sha256
  `b09dcd41b0d2edf5…`, the same content `workload.py` generates.
- Two memfds, one holding a shared object that was then loaded from
  `/proc/self/fd/N`: `malfind` flags it as `memfd-exec`, and `elfs -D`
  rebuilds it from its loaded segments (here 3,168 bytes short, the pages
  that were not resident).
- An anonymous RWX page with a NOP sled and a marker: `malfind` flags it as
  `write+exec,anonymous-exec`.
- Sockets: TCP 127.0.0.1:8765 listening with one established pair, UDP
  127.0.0.1:9876, a unix socket at `/tmp/cglens.sock`, and an abstract one
  (its name is in an unaccounted allocation, so it shows as unnamed).
- A heap object holding `CGLENS-SAMPLE-SECRET-AAAA…`, and per-thread heap
  markers, for `grep`.

Paths inside the container's writable layer read `…/fs/tmp/…`: the upper
directory's parent dentries were charged to the container runtime, not to the
container, so the chain stops there. That is how a real capture looks too.

## What was removed

A cglime capture reads slab pages whole, so the raw capture also held other
workloads' kernel objects from the lab VM: 10 co-resident tasks (`multipathd`,
`systemd-resolve`, `unattended-upgr`, `docker`, `runc` and kernel threads)
with their names and kernel state, plus their dentries, files and sockets. [`redact.py`](redact.py) zeroes every slab slot
the slab ownership map does not attribute to the target, and the slack after
the last slot:

| | |
|---|---|
| Slab pages | 664 |
| Target objects kept | 2,509 |
| Foreign dentries kept | 2, the parent chain of the container's own paths |
| Slots zeroed | 15,165 (1,323,558 non-zero bytes) |

Everything charged to the target is unchanged: its pages, page tables, kernel
stacks and slab objects, and the sidecars (BTF, kernel.json, pagemeta.bin,
slabs.json). The kernel addresses in them describe a VM boot that no longer
exists.

The result is a derivative, not evidence. `manifest.json` keeps the original
dump hash under `redaction.derived_from` and records the redacted one as
`lime_sha256`, so `cglime.py bundle verify` checks the file that is published.

## How it was checked

`redact.py` does all of this and exits non-zero if any of it fails.

- `cglime.py bundle verify` passes.
- `pslist`, `cmdline`, `envars`, `maps`, `lsof`, `files` (target inodes),
  `sockstat`, `elfs` and `malfind` give identical rows on the raw and the
  redacted capture. `psscan` goes from 15 tasks to 5: the two processes and
  their threads, no co-resident task.
- Every member of both bundles is searched for identifiers of the machines
  involved (lab network, host paths, user and host names) and for common secret
  formats. The raw capture had one hit, the lab subnet, in memory the
  redaction zeroed; the redacted one has none. The only secret-format hits are five lines of
  documentation inside the image's own `openssl.cnf` and Python's `pwd`
  module, such as `# input_password = secret`.

## Rebuilding it

On a Docker host that runs nothing you would not publish, as root, with a
cglime checkout next to this one:

```bash
sudo samples/make_sample.sh ../cglime /tmp/sample     # -> /tmp/sample/raw.cglime
python3 samples/redact.py /tmp/sample/raw.cglime /tmp/sample/out \
    --cglime ../cglime --forbid '<your hostname>' --forbid '<your LAN prefix>'
```

The capture differs on every run (addresses, PIDs, timing), so the hash will
not match; the contents above will. `make_sample.sh` drops the page cache
before starting the workload, because reclaim inside a frozen container
evicts files before they are read (cglime README, "The freeze gap").
