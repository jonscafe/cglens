"""Per object ownership from a v2 capture's slabs.json, by address containment.

A slab object is often a larger struct with the interesting one embedded in
it: an ext4 inode is `ext4_inode_info.vfs_inode`, a socket inode lives in
`socket_alloc`. So ownership is looked up by which object slot CONTAINS an
address, not by an exact start match.
"""
from __future__ import annotations

import bisect

PAGE = 4096


class SlabMap:
    """cglime-slabs/2 records object indices. /1 files written on 7.x can hold
    vector offsets instead (G16: an in-object slabobj_ext read at 8 byte steps,
    index 24 meaning object 1 of a stride-192 slab) and never cover objects
    past index 63 (G17).

    Both are repaired here when the capture allows it. An in-object entry sits
    inside the slab page itself, so with the page captured (it is: the page is
    why the slab is listed) and the target objcgs known (kernel.json), every
    object's owner is re-read straight from the dump. Where that is not
    possible, /1 offsets are converted to object indices and the slab is
    marked incomplete.
    """

    def __init__(self, slabs_doc: dict, page_offset_base: int, pagemeta=None,
                 phys=None, targets=None):
        caches = slabs_doc.get("caches") or {}
        v1 = slabs_doc.get("format") == "cglime-slabs/1"
        tgt = {int(t, 16) if isinstance(t, str) else int(t) for t in (targets or [])}
        self.stats = {"slabs": 0, "in_object": 0, "recomputed_from_dump": 0,
                      "converted_v1_offsets": 0, "incomplete": 0}
        self.entries: list[tuple[int, int, int, str, frozenset]] = []
        for s in slabs_doc.get("slabs") or []:
            c = caches.get(s.get("cache")) or {}
            size = c.get("size")
            if not size:
                continue
            self.stats["slabs"] += 1
            base = page_offset_base + s["head_pfn"] * PAGE
            end = base + s.get("pages", 1) * PAGE
            owned = set(s.get("owned") or ())
            raw = pagemeta.struct_page(s["head_pfn"]) if pagemeta is not None else None
            stride = s.get("stride")
            if stride is None and raw is not None:
                stride = int.from_bytes(raw[44:48], "little") or 8
            stride = stride or 8
            objects = s.get("objects") or (end - base) // size
            if stride != 8:
                self.stats["in_object"] += 1
                redone = self._recompute(raw, phys, page_offset_base, objects, stride, tgt)
                if redone is not None:
                    owned = redone
                    self.stats["recomputed_from_dump"] += 1
                elif v1:
                    step = stride // 8
                    owned = {i // step for i in owned if i % step == 0}
                    self.stats["converted_v1_offsets"] += 1
                    self.stats["incomplete"] += 1
            elif v1 and objects > 64:
                self.stats["incomplete"] += 1
            # /1 files also carry indices PAST the slab's object count: entries
            # read beyond the end of a short objcg vector, i.e. from a
            # neighbouring slab's vector (G17). They say nothing about this slab.
            # A slab listed only because of such an index was captured by
            # mistake, and all its objects are someone else's.
            if v1:
                oob = {i for i in owned if i >= objects}
                if oob:
                    owned -= oob
                    self.stats["out_of_range_discarded"] = \
                        self.stats.get("out_of_range_discarded", 0) + 1
                    if not owned:
                        self.stats["slabs_captured_by_mistake"] = \
                            self.stats.get("slabs_captured_by_mistake", 0) + 1
            self.entries.append((base, end, size, c.get("name") or "?", frozenset(owned)))
        self.entries.sort()
        self._starts = [e[0] for e in self.entries]

    @staticmethod
    def _recompute(raw, phys, pob, objects, stride, targets):
        if raw is None or phys is None or not targets:
            return None
        vec = int.from_bytes(raw[56:64], "little") & ~0x7
        if vec < pob:
            return None
        out = set()
        for k in range(objects):
            v = phys.u64(vec - pob + k * stride)
            if v is None:
                return None
            if v & ~0x7 in targets:
                out.add(k)
        return out

    def __len__(self) -> int:
        return len(self.entries)

    def lookup(self, va: int) -> tuple[str, int, bool] | None:
        """(cache name, object index, owned by target) for the slot holding va."""
        k = bisect.bisect_right(self._starts, va) - 1
        if k < 0:
            return None
        base, end, size, name, owned = self.entries[k]
        if va >= end:
            return None
        idx = (va - base) // size
        return name, idx, idx in owned

    def slot_start(self, va: int) -> int | None:
        """Start address of the object slot holding va, or None if unmapped."""
        k = bisect.bisect_right(self._starts, va) - 1
        if k < 0:
            return None
        base, end, size, _name, _owned = self.entries[k]
        if va >= end:
            return None
        return base + (va - base) // size * size

    def owned(self, va: int) -> bool | None:
        hit = self.lookup(va)
        return None if hit is None else hit[2]

    def objects(self, cache_names: set[str]):
        """(object va, cache name, owned) for every slot of the named caches."""
        for base, end, size, name, owned in self.entries:
            if name not in cache_names:
                continue
            for i in range((end - base) // size):
                yield base + i * size, name, i in owned
