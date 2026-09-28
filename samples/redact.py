#!/usr/bin/env python3
"""Turn the raw sample capture into the one that is published, and prove it.

    python3 samples/redact.py <raw.cglime> <out dir> --cglime <cglime checkout>

What is removed
---------------
A cglime capture takes slab pages whole, because a page is the unit it can
read. Every other object on those pages belongs to some other workload on the
capture host: other containers' dentries, files, sockets, tasks. The slab
ownership map (slabs.json, repaired by cglens exactly as analysis reads it)
says which object slots are the target's. Everything else on a slab page is
zeroed: foreign objects, free objects (which still hold whatever they held
last), and the slack after the last slot.

What is kept
------------
Every page and slab object charged to the target, and the sidecars unchanged.
One kind of foreign object is kept: a dentry on the parent chain of a dentry
the target owns or opens. The overlay root and directories like /usr and /tmp
are usually looked up first by the runtime, so they are charged to it, and
without them every path the target has breaks at the first foreign parent.
Their content is a path component that the target's own paths already show.
The workload (workload.py) is synthetic: its "secrets" are the marker string.
Kernel addresses (KASLR base, direct map base) of the capture host remain; they
describe a VM boot that no longer exists.

The result is a derivative, not evidence. Its manifest keeps the original dump
hash under `redaction.derived_from`, and records the new one as `lime_sha256`
so that `cglime.py bundle verify` checks the file that is actually shipped.

What is checked
---------------
1. `cglime.py bundle verify` on the output.
2. Every plugin run on both captures, compared row by row for the target's
   processes. Differences are listed, not hidden.
3. A pattern scan of every member of both bundles for identifiers of the
   machines involved and for common secret formats. The redacted bundle must
   have no hit on the first list.
Quiet on success: one summary line; the full record goes to redaction.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from lens.core.image import Image  # noqa: E402

LIME_MAGIC = 0x4C694D45
LIME_HDR = struct.Struct("<IIQQ8x")
PAGE = 4096

STEM_OF = {"memory.lime": ".lime", "manifest.json": ".manifest.json",
           "pslist.json": ".pslist.json", "vmlinux.btf": ".btf",
           "kernel.json": ".kernel.json", "pagemeta.bin": ".pagemeta.bin",
           "slabs.json": ".slabs.json"}

PLUGINS = ["pslist", "cmdline", "envars", "maps", "lsof", "files", "sockstat",
           "elfs", "malfind"]

# Identifiers that must not appear anywhere in the published sample. Extend
# with --forbid for the machines a new sample is taken on.
FORBID = [
    rb"192\.168\.50\.", rb"10\.0\.2\.", rb"/mnt/c/", rb"C:\\Users", rb"research-dir",
    rb"docker-memdump", rb"/home/ubuntu/w", rb"vmssh", rb"cglens_live",
    rb"CGLX7f3a",
]
# Formats worth a look wherever they turn up. Hits are reported with context.
SECRETS = {
    "private_key": rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "aws_key_id": rb"AKIA[0-9A-Z]{16}",
    "github_token": rb"gh[pousr]_[A-Za-z0-9]{36}",
    "slack_token": rb"xox[abprs]-[A-Za-z0-9-]{10,}",
    "jwt": rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.",
    "bearer": rb"[Bb]earer [A-Za-z0-9._~+/-]{20,}",
    "password_assign": rb"(?i)pass(?:word|wd)?\s*[=:]\s*[^\s\x00'\"]{4,}",
}


def lime_ranges(buf: bytes) -> list[tuple[int, int, int]]:
    out, off = [], 0
    while off + LIME_HDR.size <= len(buf):
        magic, _ver, s, e = LIME_HDR.unpack_from(buf, off)
        if magic != LIME_MAGIC:
            raise SystemExit(f"bad LiME header at {off}")
        off += LIME_HDR.size
        out.append((s, e + 1, off))
        off += e + 1 - s
    return out


def dentry_ancestors(img, sm) -> set[int]:
    """Foreign dentries on the parent chain of a dentry the target reaches."""
    from lens.core.kernel import is_kptr
    from lens.session import Session
    k = Session(img).k
    d_parent = k.off("dentry", "d_parent")
    f_dentry = k.off("file", "f_path.dentry")
    bf_user = (k.off("backing_file", "user_path.dentry")
               if k.has("backing_file", "user_path.dentry") else None)
    starts = []
    for base, _end, size, name, owned in sm.entries:
        for i in owned:
            va = base + i * size
            if name == "dentry":
                starts.append(va)
            elif "filp" in name:
                starts.append(k.dmap.u64(va + f_dentry))
                if name == "bfilp" and bf_user is not None:
                    starts.append(k.dmap.u64(va + bf_user))
    keep: set[int] = set()
    for d in starts:
        for _ in range(64):
            if not is_kptr(d):
                break
            hit = sm.lookup(d)
            if hit is None or hit[0] != "dentry" or sm.slot_start(d) != d:
                break
            if not hit[2]:
                keep.add(d)
            p = k.dmap.u64(d + d_parent)
            if p is None or p == d:
                break
            d = p
    return keep


class Zeroer:
    def __init__(self, buf: bytearray, ranges):
        self.buf, self.ranges = buf, ranges
        self.bytes = 0

    def zero(self, pa: int, n: int) -> None:
        end = pa + n
        for s, e, off in self.ranges:
            lo, hi = max(pa, s), min(end, e)
            if lo < hi:
                seg = self.buf[off + lo - s: off + hi - s]
                self.bytes += len(seg) - seg.count(0)
                self.buf[off + lo - s: off + hi - s] = bytes(hi - lo)


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_plugin(bundle: str, plugin: str, out: str) -> dict:
    p = subprocess.run([sys.executable, os.path.join(ROOT, "cglens.py"), plugin, bundle,
                        "--json", "-o", out], capture_output=True, text=True, timeout=900)
    if p.returncode != 0:
        return {"error": (p.stderr or p.stdout)[-2000:]}
    return json.load(open(out, encoding="utf-8"))


def target_rows(doc: dict, plugin: str) -> list:
    rows = doc.get("rows") or []
    if plugin == "files":
        rows = [r for r in rows if r.get("owner") == "objcg"]
    return rows


def scan_patterns(bundle: str, forbid: list[bytes]) -> dict:
    res: dict = {"forbidden": {}, "secrets": {}}
    with zipfile.ZipFile(bundle) as z:
        for name in z.namelist():
            data = z.read(name)
            for pat in forbid:
                n = len(re.findall(pat, data))
                if n:
                    res["forbidden"].setdefault(pat.decode(), {})[name] = n
            for label, pat in SECRETS.items():
                for m in re.finditer(pat, data):
                    ctx = data[max(0, m.start() - 24): m.end() + 24]
                    res["secrets"].setdefault(label, []).append(
                        {"member": name, "offset": m.start(),
                         "context": ctx.decode("latin-1").encode("unicode_escape").decode()})
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("raw", help="raw capture from make_sample.sh")
    ap.add_argument("out", help="output directory")
    ap.add_argument("--cglime", required=True, help="cglime checkout (bundle create/verify)")
    ap.add_argument("--name", default="cglens-sample")
    ap.add_argument("--forbid", action="append", default=[],
                    help="extra identifier (regex) that must not appear; repeatable")
    args = ap.parse_args()
    forbid = FORBID + [f.encode() for f in args.forbid]
    os.makedirs(args.out, exist_ok=True)
    report: dict = {"raw": os.path.basename(args.raw)}

    img = Image(args.raw)
    sm = img.slabmap
    if sm is None:
        raise SystemExit("no slab ownership map: only a v2 capture can be redacted this way")
    pob = img.page_offset_base
    with zipfile.ZipFile(args.raw) as z:
        members = {n: z.read(n) for n in z.namelist()}
    lime = bytearray(members["memory.lime"])
    zr = Zeroer(lime, lime_ranges(lime))

    ancestors = dentry_ancestors(img, sm)
    kept = foreign = 0
    for base, end, size, _name, owned in sm.entries:
        slots = (end - base) // size
        for i in range(slots):
            if i in owned or base + i * size in ancestors:
                kept += 1
            else:
                foreign += 1
                zr.zero(base - pob + i * size, size)
        if base + slots * size < end:
            zr.zero(base - pob + slots * size, end - (base + slots * size))
    report["slabs"] = {"pages_listed": len(sm.entries), "objects_kept": kept,
                       "foreign_dentry_ancestors_kept": len(ancestors),
                       "slots_zeroed": foreign, "nonzero_bytes_zeroed": zr.bytes,
                       "repairs": sm.stats}

    tmp = tempfile.mkdtemp(prefix="cglens-redact-")
    try:
        stem = os.path.join(tmp, args.name)
        man = json.loads(members["manifest.json"])
        man["redaction"] = {
            "tool": "cglens samples/redact.py",
            "derived_from": {"lime_sha256": man.get("lime_sha256"),
                             "bundle_sha256": sha256(open(args.raw, "rb").read())},
            "method": ("slab slots the slab ownership map does not attribute to the "
                       "target, and slab slack, zeroed, except dentries on the parent "
                       "chain of one the target reaches; everything else unchanged"),
            "foreign_dentry_ancestors_kept": len(ancestors),
            "slots_zeroed": foreign, "nonzero_bytes_zeroed": zr.bytes,
            "note": "a derivative for demonstration, not evidence",
        }
        man["lime_sha256"] = sha256(bytes(lime))
        for member, suffix in STEM_OF.items():
            if member not in members:
                continue
            data = bytes(lime) if member == "memory.lime" else (
                json.dumps(man, indent=2).encode() if member == "manifest.json"
                else members[member])
            with open(stem + suffix, "wb") as f:
                f.write(data)
        cg = os.path.join(args.cglime, "cglime.py")
        subprocess.run([sys.executable, cg, "bundle", "create", stem + ".lime",
                        "--case-id", "CGLENS-SAMPLE", "--operator", "cglens-sample",
                        "--notes", "redacted derivative of a synthetic workload; see "
                        "manifest.json redaction"], check=True, capture_output=True)
        out_bundle = os.path.join(args.out, args.name + ".cglime")
        shutil.copyfile(stem + ".cglime", out_bundle)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    v = subprocess.run([sys.executable, cg, "bundle", "verify", out_bundle],
                       capture_output=True, text=True)
    report["bundle_verify"] = {"returncode": v.returncode, "tail": v.stdout[-600:]}
    report["sha256"] = sha256(open(out_bundle, "rb").read())
    report["bytes"] = os.path.getsize(out_bundle)

    cmp: dict = {}
    work = tempfile.mkdtemp(prefix="cglens-cmp-")
    try:
        for plugin in PLUGINS:
            a = run_plugin(args.raw, plugin, os.path.join(work, f"raw_{plugin}.json"))
            b = run_plugin(out_bundle, plugin, os.path.join(work, f"red_{plugin}.json"))
            if "error" in a or "error" in b:
                cmp[plugin] = {"error": a.get("error") or b.get("error")}
                continue
            ra, rb = target_rows(a, plugin), target_rows(b, plugin)
            ka = [json.dumps(r, sort_keys=True) for r in ra]
            kb = [json.dumps(r, sort_keys=True) for r in rb]
            only_a = [json.loads(x) for x in ka if x not in set(kb)]
            only_b = [json.loads(x) for x in kb if x not in set(ka)]
            cmp[plugin] = {"rows_raw": len(ra), "rows_redacted": len(rb),
                           "identical": ka == kb,
                           "only_raw": only_a[:20], "only_redacted": only_b[:20]}
        for label, bundle in (("raw", args.raw), ("redacted", out_bundle)):
            ps = run_plugin(bundle, "psscan", os.path.join(work, f"{label}_psscan.json"))
            rows = ps.get("rows") or []
            cmp.setdefault("psscan", {})[label] = {
                "tasks": len(rows),
                "co_resident": sorted({r["comm"] for r in rows if r.get("ownership") != "owned"})}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    report["compare"] = cmp

    report["patterns_raw"] = scan_patterns(args.raw, forbid)
    report["patterns_redacted"] = scan_patterns(out_bundle, forbid)

    with open(os.path.join(args.out, "redaction.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    problems = []
    if report["bundle_verify"]["returncode"] != 0:
        problems.append("bundle verify failed")
    if report["patterns_redacted"]["forbidden"]:
        problems.append(f"forbidden identifiers present: {report['patterns_redacted']['forbidden']}")
    for plugin, c in cmp.items():
        if plugin == "psscan":
            if c["redacted"]["co_resident"]:
                problems.append(f"co-resident tasks remain: {c['redacted']['co_resident']}")
        elif "error" in c:
            problems.append(f"{plugin}: {c['error'][-300:]}")
    changed = [p for p, c in cmp.items() if p != "psscan" and not c.get("identical", True)]
    status = "FAIL" if problems else "OK"
    print(f"[{status}] {out_bundle} | {report['bytes']} bytes sha256 {report['sha256'][:16]} | "
          f"{foreign} foreign slots zeroed ({zr.bytes} nonzero bytes) | "
          f"plugins changed: {changed or 'none'} | secret-format hits: "
          f"{ {k: len(v) for k, v in report['patterns_redacted']['secrets'].items()} }")
    for p in problems:
        print(f"  {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
