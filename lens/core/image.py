"""Open a cglime capture, in whatever shape it arrives.

Accepted inputs:

  X.cglime                 bundle (ZIP): memory.lime, manifest.json, and in a
                           v2 capture also vmlinux.btf, kernel.json, pagemeta.bin
                           and slabs.json
  X.lime                   plain dump; sidecars X.manifest.json, X.btf,
                           X.kernel.json, X.pagemeta.bin, X.slabs.json are
                           picked up when they sit beside it

Everything that cglens knows about the kernel comes from these files. What is
missing is reported as missing; nothing is guessed from the version string.

BTF is resolved in this order, and the source is recorded in every report:

  1. inside the bundle (v2 capture)       -> "capture"
  2. X.btf beside the dump                -> "sidecar"
  3. --btf PATH                           -> "analyst"
  4. --btf-dir DIR / <kernel_release>.btf -> "analyst-dir"

Sources 3 and 4 are an analyst's claim that the BTF matches the kernel that
was captured. The report says so, because nothing in a pre-v2 capture can
prove it.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import shutil
import tempfile
import zipfile

from .btf import BTF
from .layers import DirectMap, PhysicalLayer

SIDECARS = {
    "manifest.json": ".manifest.json",
    "vmlinux.btf": ".btf",
    "kernel.json": ".kernel.json",
    "pagemeta.bin": ".pagemeta.bin",
    "slabs.json": ".slabs.json",
    "pslist.json": ".pslist.json",
}


class ImageError(Exception):
    pass


class Image:
    """A capture opened for analysis."""

    def __init__(self, path: str, btf: str | None = None, btf_dir: str | None = None,
                 use_sidecars: bool = True):
        """use_sidecars=False reads only the dump and its manifest, ignoring every
        v2 sidecar: the ablation that shows what a pre-v2 capture supports."""
        self.path = os.path.abspath(path)
        self.use_sidecars = use_sidecars
        self.files: dict[str, str] = {}
        self.bundle_index: dict | None = None
        self._tmp: str | None = None
        if zipfile.is_zipfile(self.path):
            self._open_bundle()
        else:
            self._open_loose()
        if "memory.lime" not in self.files:
            raise ImageError(f"{path}: no LiME dump found")
        if not use_sidecars:
            self.files = {k: v for k, v in self.files.items()
                          if k in ("memory.lime", "manifest.json")}

        self.manifest: dict = self._json("manifest.json") or {}
        self.kernel_meta: dict = self._json("kernel.json") or {}
        self.slabs: dict | None = self._json("slabs.json")
        self._slabmap = None
        self.capture_pslist: dict | None = self._json("pslist.json")
        self.phys = PhysicalLayer(self.files["memory.lime"])

        self.page_offset_base = self._hexval("page_offset_base")
        self.vmemmap_base = self._hexval("vmemmap_base")
        self.la57 = bool(self.kernel_meta.get("la57", False))
        self.kernel_release = (self.kernel_meta.get("kernel_release")
                               or self.manifest.get("kernel_release") or "")
        self.dmap = DirectMap(self.phys, self.page_offset_base, self.la57) \
            if self.page_offset_base is not None else None

        self.btf: BTF | None = None
        self.btf_source: str | None = None
        self.btf_note: str = ""
        self._load_btf(btf, btf_dir)
        self.pagemeta = None
        if "pagemeta.bin" in self.files:
            from .pagemeta import PageMeta
            self.pagemeta = PageMeta(self.files["pagemeta.bin"])

    # ----------------------------------------------------------- open paths
    def _open_bundle(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="cglens-")
        atexit.register(shutil.rmtree, self._tmp, True)
        with zipfile.ZipFile(self.path) as z:
            names = set(z.namelist())
            if "BUNDLE.json" in names:
                self.bundle_index = json.loads(z.read("BUNDLE.json"))
            for member in ("memory.lime", *SIDECARS):
                if member in names:
                    self.files[member] = z.extract(member, self._tmp)

    def _open_loose(self) -> None:
        p = self.path
        if p.endswith(".manifest.json"):
            p = p[: -len(".manifest.json")] + ".lime"
        base = p[:-5] if p.endswith(".lime") else p
        if not os.path.exists(p):
            if not os.path.exists(self.path):
                hint = ""
                if self.path.endswith(".cglime"):
                    lime = self.path[: -len(".cglime")] + ".lime"
                    hint = (f"; the dump itself can be read directly ({lime})"
                            if os.path.exists(lime) else "")
                    hint += "; `cglime.py bundle create <dump.lime>` makes the bundle"
                raise ImageError(f"{self.path}: no such file{hint}")
            raise ImageError(f"{self.path}: not a .cglime bundle, and no .lime dump found")
        self.files["memory.lime"] = p
        for member, suffix in SIDECARS.items():
            cand = base + suffix
            if os.path.exists(cand):
                self.files[member] = cand

    def _json(self, member: str) -> dict | None:
        p = self.files.get(member)
        if not p:
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def _hexval(self, key: str) -> int | None:
        for src in (self.kernel_meta, self.manifest):
            v = src.get(key)
            if v is None:
                continue
            return int(v, 16) if isinstance(v, str) else int(v)
        return None

    def _load_btf(self, btf: str | None, btf_dir: str | None) -> None:
        if "vmlinux.btf" in self.files:
            src = "capture" if self.bundle_index else "sidecar"
            self.btf = BTF.from_file(self.files["vmlinux.btf"])
            self.btf_source = src
            want = self.kernel_meta.get("btf_sha256")
            if want and want != self.btf.sha256:
                raise ImageError("embedded BTF does not match the hash the capture recorded")
            return
        cands: list[tuple[str, str]] = []
        if btf:
            cands.append((btf, "analyst"))
        dirs = [d for d in (btf_dir, os.environ.get("CGLENS_BTF_DIR")) if d]
        for d in dirs:
            if self.kernel_release:
                cands.append((os.path.join(d, self.kernel_release + ".btf"), "analyst-dir"))
        for p, src in cands:
            if os.path.exists(p):
                self.btf = BTF.from_file(p)
                self.btf_source = src
                self.btf_note = ("BTF supplied by the analyst, not by the capture: it is "
                                 "assumed, not proven, to match the captured kernel")
                return
        self.btf_note = ("no BTF: pass --btf or --btf-dir, or capture with cglime v2 "
                         "which embeds it")

    # ------------------------------------------------------------ helpers
    @property
    def slabmap(self):
        """Per object ownership (v2 slabs.json), or None on older captures."""
        if self._slabmap is None and self.slabs and self.page_offset_base is not None:
            from .slabmap import SlabMap
            # in-object entries (G16) are re-read from the dump; that needs the
            # struct slab records and the target objcgs of a 7.x capture
            targets = self.kernel_meta.get("targets") \
                if self.kernel_meta.get("memcg_data_is_objcg") else None
            self._slabmap = SlabMap(self.slabs, self.page_offset_base,
                                    pagemeta=self.pagemeta, phys=self.phys, targets=targets)
        return self._slabmap

    def require_btf(self) -> BTF:
        if self.btf is None:
            raise ImageError(self.btf_note)
        return self.btf

    def require_dmap(self) -> DirectMap:
        if self.dmap is None:
            raise ImageError("page_offset_base unknown: this capture did not record it "
                             "(userspace acquisition path?). Kernel objects cannot be "
                             "located without it")
        return self.dmap

    @property
    def capture_format(self) -> str:
        if "kernel.json" in self.files:
            return "cglime-v2 (self-describing)"
        if self.bundle_index:
            return "cglime bundle v1"
        return "loose LiME + manifest" if self.manifest else "bare LiME"

    @property
    def has_pagetables_hint(self) -> bool | None:
        """Did the acquisition include kmem pages (page tables)? From the manifest."""
        scan = self.manifest.get("scan")
        if isinstance(scan, dict):
            # memcg_scan records kmem_target from the G11 fix onwards; a scan
            # block without it predates kmem attribution: no page tables.
            return bool(scan.get("kmem_target"))
        if self.kernel_meta.get("kmem_pages") is not None:
            return bool(self.kernel_meta["kmem_pages"])
        return None

    def sha256(self) -> str:
        h = hashlib.sha256()
        with open(self.files["memory.lime"], "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def close(self) -> None:
        self.phys.close()
