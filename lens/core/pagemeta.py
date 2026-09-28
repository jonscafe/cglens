"""Reader for pagemeta.bin, the struct page records a v2 capture carries.

Offline, the dump holds page CONTENTS but not the kernel's description of each
page: the vmemmap is kernel memory, never charged to the container, so it is
never in the dump. That description is what says a page is a slab page and
of which cache, which file and offset a page cache page belongs to, and which
folio a tail page is part of. It exists only on the live host, so cglime v2
copies the raw `struct page` of every captured PFN at acquisition time.

Layout (little endian):

    header   8s  magic  b"CGPGMETA"
             I   version (1)
             I   sizeof_struct_page
             Q   record count
             Q   vmemmap_base
    record   Q   pfn
             B   class  (see CLASSES)
             7x  pad
             N   raw struct page bytes, N = sizeof_struct_page

Classes are the scanner's decision at capture time, recorded so the offline
side does not have to re-derive them from page flags whose bit numbers move
between kernels.
"""
from __future__ import annotations

import struct

MAGIC = b"CGPGMETA"
HDR = struct.Struct("<8sIIQQ")
REC = struct.Struct("<QB7x")

CLASSES = {0: "regular", 1: "kmem", 2: "slab", 3: "compound-tail", 4: "other"}
CLASS_CODES = {v: k for k, v in CLASSES.items()}


class PageMeta:
    def __init__(self, path: str):
        with open(path, "rb") as f:
            raw = f.read()
        magic, ver, psz, count, vmemmap = HDR.unpack_from(raw, 0)
        if magic != MAGIC:
            raise ValueError(f"{path}: not a pagemeta file")
        self.version = ver
        self.sizeof_page = psz
        self.vmemmap_base = vmemmap
        self._raw = raw
        self._index: dict[int, tuple[int, int]] = {}   # pfn -> (class, offset of struct page)
        pos = HDR.size
        step = REC.size + psz
        for _ in range(count):
            pfn, cls = REC.unpack_from(raw, pos)
            self._index[pfn] = (cls, pos + REC.size)
            pos += step

    def __len__(self) -> int:
        return len(self._index)

    def __contains__(self, pfn: int) -> bool:
        return pfn in self._index

    def page_class(self, pfn: int) -> str | None:
        hit = self._index.get(pfn)
        return CLASSES.get(hit[0]) if hit else None

    def struct_page(self, pfn: int) -> bytes | None:
        hit = self._index.get(pfn)
        if not hit:
            return None
        return self._raw[hit[1]:hit[1] + self.sizeof_page]

    def pfns(self, cls: str | None = None):
        code = CLASS_CODES.get(cls) if cls else None
        for pfn, (c, _o) in self._index.items():
            if code is None or c == code:
                yield pfn

    def pfn_of_page_ptr(self, ptr: int) -> int | None:
        """struct page * (vmemmap virtual) -> PFN."""
        off = ptr - self.vmemmap_base
        if off < 0 or off % self.sizeof_page:
            return None
        return off // self.sizeof_page

    def histogram(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for c, _o in self._index.values():
            name = CLASSES.get(c, str(c))
            out[name] = out.get(name, 0) + 1
        return out


def write(path: str, sizeof_page: int, vmemmap_base: int,
          records: list[tuple[int, int, bytes]]) -> int:
    """records: (pfn, class_code, raw struct page). Returns bytes written."""
    records = sorted(records)
    with open(path, "wb") as f:
        f.write(HDR.pack(MAGIC, 1, sizeof_page, len(records), vmemmap_base))
        for pfn, cls, raw in records:
            if len(raw) != sizeof_page:
                raise ValueError(f"pfn {pfn}: struct page is {len(raw)} bytes")
            f.write(REC.pack(pfn, cls))
            f.write(raw)
        return f.tell()
