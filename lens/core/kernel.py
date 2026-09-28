"""Typed access to kernel objects in the direct map.

`Obj` reads a whole struct once and answers member reads from that buffer,
using BTF for offsets, widths and signedness. When the object is not in the
dump, `Obj.present` is False and every read returns None: absence is a normal
outcome in a scoped capture, not an exception.
"""
from __future__ import annotations

from .btf import BTF, K_ARRAY, K_PTR
from .image import Image
from .layers import AddressSpace, DirectMap

KERNEL_HALF = 0xFFFF800000000000
LIST_POISON1 = 0xDEAD000000000100
LIST_POISON2 = 0xDEAD000000000122


def is_kptr(v: int | None) -> bool:
    return v is not None and v >= KERNEL_HALF


class Kernel:
    def __init__(self, img: Image):
        self.img = img
        self.btf: BTF = img.require_btf()
        self.dmap: DirectMap = img.require_dmap()
        self.phys = img.phys
        self._sizes: dict[str, int] = {}

    def size(self, struct_name: str) -> int:
        s = self._sizes.get(struct_name)
        if s is None:
            s = self._sizes[struct_name] = self.btf.struct_size(struct_name)
        return s

    def off(self, struct_name: str, path: str) -> int:
        return self.btf.offset(struct_name, path)

    def has(self, struct_name: str, path: str) -> bool:
        return self.btf.has_field(struct_name, path)

    def obj(self, struct_name: str, va: int | None) -> "Obj":
        return Obj(self, struct_name, va)

    def container_of(self, member_va: int, struct_name: str, path: str) -> "Obj":
        return Obj(self, struct_name, member_va - self.off(struct_name, path))

    def read_cstr(self, va: int | None, maxlen: int = 256) -> str | None:
        if not self.dmap.contains(va or 0):
            return None
        data = self.dmap.read(va, maxlen)
        if data is None:
            # the string may end before a page boundary that is missing
            room = 4096 - (va & 0xFFF)
            data = self.dmap.read(va, min(maxlen, room))
            if data is None:
                return None
        nul = data.find(b"\x00")
        if nul < 0:
            return None
        return data[:nul].decode("utf-8", "replace")

    def address_space(self, pgd_va: int) -> AddressSpace | None:
        pa = self.dmap.pa(pgd_va)
        if pa is None:
            return None
        return AddressSpace(self.phys, pa, self.img.la57)


class Obj:
    """A struct in the direct map. May be PARTIAL: a large object (task_struct
    spans several pages) can straddle a page the capture does not hold. Reads of
    members inside a missing span return None; the rest of the object is used.
    """
    __slots__ = ("k", "type", "va", "buf", "missing")

    def __init__(self, k: Kernel, struct_name: str, va: int | None):
        self.k = k
        self.type = struct_name
        self.va = va
        self.buf: bytes | None = None
        self.missing: list[tuple[int, int]] = []
        if va and k.dmap.contains(va):
            size = k.size(struct_name)
            got = k.dmap.read_padded(va, size)
            if got is not None:
                buf, missing = got
                if not missing:
                    self.buf = buf
                elif missing[0][0] > 0:          # the start of the object is there
                    self.buf, self.missing = buf, missing

    @classmethod
    def from_bytes(cls, k: Kernel, struct_name: str, va: int, buf: bytes) -> "Obj":
        o = cls.__new__(cls)
        o.k, o.type, o.va, o.buf, o.missing = k, struct_name, va, buf, []
        return o

    @property
    def present(self) -> bool:
        return self.buf is not None

    @property
    def complete(self) -> bool:
        return self.buf is not None and not self.missing

    def _span_ok(self, off: int, n: int) -> bool:
        if self.buf is None:
            return False
        for mo, ml in self.missing:
            if off < mo + ml and mo < off + n:
                return False
        return True

    @property
    def pa(self) -> int | None:
        return self.k.dmap.pa(self.va) if self.va else None

    def __bool__(self) -> bool:
        return self.present

    def _field(self, path: str):
        return self.k.btf.field(self.type, path)

    def has(self, path: str) -> bool:
        return self.k.has(self.type, path)

    def addr(self, path: str) -> int:
        return self.va + self._field(path).offset

    def int(self, path: str) -> int | None:
        if self.buf is None:
            return None
        f = self._field(path)
        if not self._span_ok(f.offset, min(f.size, 8) or 8):
            return None
        if f.bitfield_size:
            n = (f.bit_offset + f.bitfield_size + 7) // 8
            raw = self.buf[f.offset:f.offset + n]
            return (int.from_bytes(raw, "little") >> f.bit_offset) & ((1 << f.bitfield_size) - 1)
        size = min(f.size, 8) or 8
        raw = self.buf[f.offset:f.offset + size]
        if len(raw) < size:
            return None
        return int.from_bytes(raw, "little", signed=self.k.btf.is_signed(f.type_id))

    def u64_at(self, off: int) -> int | None:
        if self.buf is None or off + 8 > len(self.buf) or not self._span_ok(off, 8):
            return None
        return int.from_bytes(self.buf[off:off + 8], "little")

    def ptr(self, path: str) -> int | None:
        if self.buf is None:
            return None
        f = self._field(path)
        if not self._span_ok(f.offset, 8):
            return None
        return int.from_bytes(self.buf[f.offset:f.offset + 8], "little")

    def bytes(self, path: str, n: int | None = None) -> bytes | None:
        if self.buf is None:
            return None
        f = self._field(path)
        if not self._span_ok(f.offset, n or f.size):
            return None
        return self.buf[f.offset:f.offset + (n or f.size)]

    def cstr(self, path: str) -> str | None:
        """An inline char array such as task_struct.comm."""
        raw = self.bytes(path)
        if raw is None:
            return None
        nul = raw.find(b"\x00")
        return raw[: nul if nul >= 0 else len(raw)].decode("utf-8", "replace")

    def deref(self, path: str, struct_name: str | None = None) -> "Obj":
        """Follow a pointer member. The target type comes from BTF when not given."""
        p = self.ptr(path)
        if struct_name is None:
            t = self.k.btf.pointee(self._field(path).type_id)
            if t is None or not t.name:
                raise TypeError(f"{self.type}.{path} is not a pointer to a named struct")
            struct_name = t.name
        return Obj(self.k, struct_name, p if is_kptr(p) else None)

    def list_is_empty(self, path: str) -> bool | None:
        nxt = self.ptr(path)
        return None if nxt is None else nxt == self.addr(path)

    def is_array(self, path: str) -> bool:
        return self.k.btf.resolve(self._field(path).type_id).kind == K_ARRAY

    def is_ptr(self, path: str) -> bool:
        return self.k.btf.resolve(self._field(path).type_id).kind == K_PTR
