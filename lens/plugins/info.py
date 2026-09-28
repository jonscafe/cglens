"""What this capture is, and which analyses it can support."""
from __future__ import annotations

from ..render import Result

NAME = "info"
HELP = "capture summary and which analyses it supports"


def add_args(ap) -> None:
    pass


def run(s, args) -> Result:
    img = s.img
    m = img.manifest
    rows = []

    def add(k, v):
        rows.append({"field": k, "value": v})

    add("format", img.capture_format)
    add("acquisition_path", m.get("acquisition_path"))
    add("container_id", m.get("container_id"))
    add("cgroup", m.get("cgroup_path"))
    add("scope", (m.get("scope") or {}).get("kind") if isinstance(m.get("scope"), dict) else m.get("scope"))
    add("kernel_release", img.kernel_release)
    add("memcg_era", m.get("memcg_era") or (m.get("kernel_gate") or {}).get("memcg_era"))
    add("frozen_during_capture", m.get("cgroup_frozen_during_capture"))
    add("ranges", len(img.phys.ranges))
    add("payload_mib", round(img.phys.payload_bytes / 2**20, 2))
    add("page_offset_base", hex(img.page_offset_base) if img.page_offset_base is not None else None)
    add("vmemmap_base", hex(img.vmemmap_base) if img.vmemmap_base is not None else None)
    add("btf", f"{img.btf_source} sha256:{img.btf.sha256[:16]}" if img.btf else None)
    pages = m.get("pages") or {}
    add("pages_regular/kmem/slab", f"{pages.get('regular')}/{pages.get('kmem')}/{pages.get('slab')}")
    add("pagemeta", f"{len(img.pagemeta)} struct page records" if img.pagemeta else None)
    add("slab_ownership_map", (img.slabs or {}).get("format") if img.slabs else None)
    if img.slabmap is not None:
        add("slab_map_repairs", img.slabmap.stats)
    add("capture_pslist", bool(img.capture_pslist))

    caps = []
    kobj = img.btf is not None and img.page_offset_base is not None
    slab = m.get("slab_included")
    caps.append(("process discovery (psscan/pslist)", kobj and slab is not False,
                 "needs BTF, page_offset_base and slab pages"))
    caps.append(("VMAs (maps)", kobj and slab is not False, "same"))
    pt = img.has_pagetables_hint
    caps.append(("user memory: cmdline/envars/procdump", kobj and pt is not False,
                 "needs page tables (kmem pages, cglime >= G11 fix)"
                 + ("" if pt is not False else "; this capture has none")))
    caps.append(("definitive ownership", bool(img.slabs) or bool(img.capture_pslist),
                 "needs v2 slabs.json or capture-time pslist"))
    notes = [f"{'OK ' if ok else 'NO '} {name}: {why}" for name, ok, why in caps]
    if img.btf_note and not (img.btf_source or "").startswith("analyst"):
        notes.append(img.btf_note)
    return Result("capture info", ["field", "value"], rows, notes)
