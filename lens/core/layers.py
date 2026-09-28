"""Address spaces over a sparse LiME capture.

Three layers, stacked:

  PhysicalLayer   the LiME ranges themselves. A cglime dump is SPARSE: most of
                  physical memory is simply absent, so every read reports
                  whether the bytes were there instead of zero filling quietly.
  DirectMap       kernel virtual -> physical through page_offset_base. Every
                  slab object, page table page and struct the analysis follows
                  is reached through the direct map, and the capture records
                  page_offset_base, so no kernel page table is needed.
  AddressSpace    one process's virtual memory, walked from mm->pgd through
                  its own page tables. Those page tables are kmem pages charged
                  to the container, which cglime captures from G11 onwards.

A read that falls in a hole says why: the page is absent from the dump, the
page table that maps it is absent, or the PTE is not present (never touched,
swapped, or PROT_NONE). The difference matters in a report. "Not captured" is
a statement about the acquisition, "not present" is a statement about the
process.
"""
from __future__ import annotations

import bisect
import mmap
import struct

PAGE = 4096
LIME_MAGIC = 0x4C694D45
_HDR = struct.Struct("<IIQQQ")

# x86_64 page table entry bits
PTE_PRESENT = 1 << 0
PTE_RW = 1 << 1
PTE_USER = 1 << 2
PTE_PSE = 1 << 7
PTE_PROTNONE = 1 << 8   # _PAGE_BIT_PROTNONE aliases _PAGE_BIT_GLOBAL
PTE_NX = 1 << 63
ADDR_MASK = 0x000FFFFFFFFFF000

# Hole reasons
MISSING_PAGE = "page-not-captured"
MISSING_TABLE = "pagetable-not-captured"
NOT_PRESENT = "pte-not-present"
SWAPPED = "pte-swap-entry"


class PhysicalLayer:
    """Random access over the ranges of one LiME file (mmap, zero copy)."""

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "rb")
        size = self._fh.seek(0, 2)
        self.buf = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ) if size else b""
        self.ranges: list[tuple[int, int, int]] = []   # (pa, file_offset, length)
        pos = 0
        while pos + _HDR.size <= size:
            magic, _ver, s, e, _ = _HDR.unpack_from(self.buf, pos)
            if magic != LIME_MAGIC:
                raise ValueError(f"{path}: bad LiME magic {magic:#x} at offset {pos}")
            n = e - s + 1
            pos += _HDR.size
            if pos + n > size:
                raise ValueError(f"{path}: range {s:#x}-{e:#x} truncated")
            self.ranges.append((s, pos, n))
            pos += n
        self.ranges.sort()
        self._starts = [r[0] for r in self.ranges]
        self._by_file = sorted((fo, pa, n) for pa, fo, n in self.ranges)
        self._fstarts = [r[0] for r in self._by_file]
        self.payload_bytes = sum(r[2] for r in self.ranges)

    def close(self) -> None:
        if isinstance(self.buf, mmap.mmap):
            self.buf.close()
        self._fh.close()

    # ------------------------------------------------------------ geometry
    def _locate(self, pa: int) -> tuple[int, int, int] | None:
        k = bisect.bisect_right(self._starts, pa) - 1
        if k < 0:
            return None
        s, fo, n = self.ranges[k]
        if pa >= s + n:
            return None
        return s, fo, n

    def has(self, pa: int) -> bool:
        return self._locate(pa) is not None

    def has_page(self, pfn: int) -> bool:
        return self._locate(pfn * PAGE) is not None

    def file_to_pa(self, file_off: int) -> int | None:
        k = bisect.bisect_right(self._fstarts, file_off) - 1
        if k < 0:
            return None
        fo, pa, n = self._by_file[k]
        if file_off >= fo + n:
            return None
        return pa + (file_off - fo)

    # ---------------------------------------------------------------- read
    def read(self, pa: int, n: int) -> bytes | None:
        """All n bytes, or None if any byte is missing. Spans adjacent ranges."""
        out = bytearray()
        while n > 0:
            loc = self._locate(pa)
            if loc is None:
                return None
            s, fo, ln = loc
            take = min(n, s + ln - pa)
            out += self.buf[fo + pa - s: fo + pa - s + take]
            pa += take
            n -= take
        return bytes(out)

    def read_padded(self, pa: int, n: int) -> tuple[bytes, list[tuple[int, int]]]:
        """n bytes with missing parts zero filled, and the missing (offset, length) spans."""
        out = bytearray(n)
        missing: list[tuple[int, int]] = []
        done = 0
        while done < n:
            cur = pa + done
            loc = self._locate(cur)
            if loc is None:
                # skip to next range start or end of request
                k = bisect.bisect_right(self._starts, cur)
                nxt = self._starts[k] if k < len(self._starts) else cur + n
                gap = min(n - done, max(nxt - cur, 1))
                missing.append((done, gap))
                done += gap
                continue
            s, fo, ln = loc
            take = min(n - done, s + ln - cur)
            out[done:done + take] = self.buf[fo + cur - s: fo + cur - s + take]
            done += take
        return bytes(out), missing

    def u64(self, pa: int) -> int | None:
        loc = self._locate(pa)
        if loc is None:
            return None
        s, fo, ln = loc
        if pa + 8 > s + ln:
            d = self.read(pa, 8)
            return None if d is None else int.from_bytes(d, "little")
        o = fo + pa - s
        return int.from_bytes(self.buf[o:o + 8], "little")

    # ---------------------------------------------------------------- scan
    def find_all(self, pattern: bytes, align: int = 1):
        """Physical address of every occurrence of `pattern` (C speed search)."""
        buf = self.buf
        i = buf.find(pattern)
        while i != -1:
            pa = self.file_to_pa(i)
            if pa is not None and pa % align == 0:
                # a match straddling two ranges is not a real match
                if self.file_to_pa(i + len(pattern) - 1) == pa + len(pattern) - 1:
                    yield pa
            i = buf.find(pattern, i + 1)

    def qword_views(self):
        """(range_pa, memoryview of u64) for every range, for strided scans."""
        for pa, fo, n in self.ranges:
            if fo % 8 or n % 8:
                continue
            yield pa, memoryview(self.buf)[fo:fo + n].cast("Q")

    def pages(self):
        for pa, _fo, n in self.ranges:
            for off in range(0, n, PAGE):
                yield (pa + off) // PAGE


class DirectMap:
    """Kernel direct map: virtual = page_offset_base + physical."""

    # 64 TiB on 4-level paging, 32 PiB on 5-level. The upper bound only has to
    # reject pointers that are obviously elsewhere (vmalloc, vmemmap, text).
    def __init__(self, phys: PhysicalLayer, page_offset_base: int, la57: bool = False):
        self.phys = phys
        self.base = page_offset_base
        self.limit = page_offset_base + ((1 << 55) if la57 else (1 << 46))

    def contains(self, va: int) -> bool:
        return self.base <= va < self.limit

    def pa(self, va: int) -> int | None:
        return va - self.base if self.contains(va) else None

    def va(self, pa: int) -> int:
        return self.base + pa

    def read(self, va: int, n: int) -> bytes | None:
        pa = self.pa(va)
        return None if pa is None else self.phys.read(pa, n)

    def u64(self, va: int) -> int | None:
        pa = self.pa(va)
        return None if pa is None else self.phys.u64(pa)

    def read_padded(self, va: int, n: int) -> tuple[bytes, list[tuple[int, int]]] | None:
        pa = self.pa(va)
        return None if pa is None else self.phys.read_padded(pa, n)

    def present(self, va: int) -> bool:
        pa = self.pa(va)
        return pa is not None and self.phys.has(pa)


class Translation:
    __slots__ = ("pa", "size", "status", "pte")

    def __init__(self, pa: int | None, size: int, status: str, pte: int = 0):
        self.pa = pa
        self.size = size
        self.status = status
        self.pte = pte

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class AddressSpace:
    """A process's user address space, walked from its pgd physical address."""

    def __init__(self, phys: PhysicalLayer, pgd_pa: int, la57: bool = False):
        self.phys = phys
        self.pgd_pa = pgd_pa
        self.levels = 5 if la57 else 4
        self._cache: dict[int, Translation] = {}

    @property
    def pgd_present(self) -> bool:
        return self.phys.has(self.pgd_pa)

    def translate(self, va: int) -> Translation:
        page = va & ~0xFFF
        hit = self._cache.get(page)
        if hit is None:
            hit = self._walk(page)
            self._cache[page] = hit
        if hit.pa is None:
            return hit
        return Translation(hit.pa + (va - page), hit.size, hit.status, hit.pte)

    def _walk(self, va: int) -> Translation:
        table = self.pgd_pa
        shifts = (48, 39, 30, 21, 12) if self.levels == 5 else (39, 30, 21, 12)
        for level, shift in enumerate(shifts):
            e = self.phys.u64(table + ((va >> shift) & 0x1FF) * 8)
            if e is None:
                return Translation(None, 1 << shift, MISSING_TABLE, 0)
            last = shift == 12
            if not e & PTE_PRESENT:
                if last and e and not e & PTE_PROTNONE:
                    return Translation(None, PAGE, SWAPPED, e)
                # PROT_NONE keeps the frame; the data is still resident
                if last and e & PTE_PROTNONE:
                    pa = e & ADDR_MASK
                    st = "ok" if self.phys.has(pa) else MISSING_PAGE
                    return Translation(pa if st == "ok" else None, PAGE, st, e)
                return Translation(None, 1 << shift, NOT_PRESENT, e)
            if not last and shift in (30, 21) and e & PTE_PSE:
                size = 1 << shift
                pa = (e & ADDR_MASK & ~(size - 1)) + (va & (size - 1))
                st = "ok" if self.phys.has(pa) else MISSING_PAGE
                return Translation(pa if st == "ok" else None, PAGE, st, e)
            if last:
                pa = e & ADDR_MASK
                st = "ok" if self.phys.has(pa) else MISSING_PAGE
                return Translation(pa if st == "ok" else None, PAGE, st, e)
            table = e & ADDR_MASK
        return Translation(None, PAGE, MISSING_TABLE, 0)

    def read(self, va: int, n: int) -> tuple[bytes, list[tuple[int, int, str]]]:
        """n bytes (holes zero filled) and the holes as (va, length, reason)."""
        out = bytearray()
        holes: list[tuple[int, int, str]] = []
        end = va + n
        cur = va
        while cur < end:
            take = min(end - cur, PAGE - (cur & 0xFFF))
            t = self.translate(cur)
            data = self.phys.read(t.pa, take) if t.ok else None
            if data is None:
                out += bytes(take)
                reason = t.status if not t.ok else MISSING_PAGE
                if holes and holes[-1][0] + holes[-1][1] == cur and holes[-1][2] == reason:
                    holes[-1] = (holes[-1][0], holes[-1][1] + take, reason)
                else:
                    holes.append((cur, take, reason))
            else:
                out += data
            cur += take
        return bytes(out), holes

    def residency(self, start: int, end: int) -> dict[str, int]:
        """Page counts by translation status over [start, end)."""
        out: dict[str, int] = {}
        va = start & ~0xFFF
        while va < end:
            t = self.translate(va)
            out[t.status] = out.get(t.status, 0) + 1
            # a missing upper level table covers a large span in one step
            if t.status in (MISSING_TABLE, NOT_PRESENT) and t.size > PAGE:
                nxt = (va | (t.size - 1)) + 1
                skipped = (min(nxt, end) - va) // PAGE
                out[t.status] += max(skipped - 1, 0)
                va = nxt
                continue
            va += PAGE
        return out


def iter_user_pages(a: AddressSpace, user_top_index: int | None = None):
    """(va, pa, size) for every present user mapping, by walking the tables.

    Used for reverse mapping (physical page -> process address). Only the user
    half of the PGD is walked; tables not in the dump are skipped silently
    because their absence is already reported by translate().
    """
    import struct as _st
    levels = (48, 39, 30, 21, 12) if a.levels == 5 else (39, 30, 21, 12)
    top = user_top_index if user_top_index is not None else 256

    def table(pa):
        raw = a.phys.read(pa, 4096)
        return None if raw is None else _st.unpack("<512Q", raw)

    def walk(pa, depth, va_base):
        ents = table(pa)
        if ents is None:
            return
        shift = levels[depth]
        rng = range(top) if depth == 0 else range(512)
        for i in rng:
            e = ents[i]
            if not e & PTE_PRESENT:
                continue
            va = va_base | (i << shift)
            if depth == 0 and a.levels == 4 and va & (1 << 47):
                continue
            last = shift == 12
            if last or (shift in (30, 21) and e & PTE_PSE):
                size = 1 << shift
                base = e & ADDR_MASK & ~(size - 1)
                for off in range(0, size, PAGE):
                    if a.phys.has(base + off):
                        yield va + off, base + off, PAGE
                continue
            yield from walk(e & ADDR_MASK, depth + 1, va)

    yield from walk(a.pgd_pa, 0, 0)
