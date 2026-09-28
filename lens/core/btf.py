"""BTF type information, read offline from a blob.

cglime's `btf.py` answers one question, the byte offset of a named field, and
it reads `/sys/kernel/btf/vmlinux` on the live host. Offline analysis needs
more than offsets. To follow `task->mm->pgd` or `vma->vm_file->f_path.dentry`
the reader has to know that a member is a pointer, what it points to, how wide
an integer is, and where a field sits inside an embedded struct that is itself
inside an anonymous union. This module keeps the whole type graph and resolves
dotted member paths against it.

The blob comes from the capture (a cglime v2 bundle carries it), from a sidecar
beside the dump, or from the analyst. It is the only kernel-specific input
cglens needs; there is no ISF, no dwarf, no System.map.

Format reference: Documentation/bpf/btf.rst
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

BTF_MAGIC = 0xEB9F

(K_UNKN, K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF,
 K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC,
 K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64) = range(20)

_QUALIFIERS = (K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_TYPE_TAG)


@dataclass
class Member:
    name: str
    type_id: int
    bit_offset: int
    bitfield_size: int = 0

    @property
    def offset(self) -> int:
        return self.bit_offset // 8


@dataclass
class Type:
    id: int
    kind: int
    name: str
    size: int = 0          # STRUCT/UNION/INT/ENUM/FLOAT
    ref: int = 0           # PTR/TYPEDEF/qualifiers: referenced type
    members: list[Member] = field(default_factory=list)
    elem: int = 0          # ARRAY element type
    nelems: int = 0        # ARRAY length
    int_signed: bool = False
    enum_values: dict[str, int] | None = None


@dataclass(frozen=True)
class Field:
    """A resolved member: absolute offset inside the outer struct and its type."""
    offset: int
    type_id: int
    size: int
    bit_offset: int = 0     # inside the byte at `offset`, bitfields only
    bitfield_size: int = 0


class BTF:
    def __init__(self, blob: bytes, source: str = "<bytes>"):
        self.raw = bytes(blob)
        self.source = source
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        magic, ver, flags, hdr_len = struct.unpack_from("<HBBI", self.raw, 0)
        if magic != BTF_MAGIC:
            raise ValueError(f"{source}: not a BTF blob (magic {magic:#x})")
        type_off, type_len, str_off, str_len = struct.unpack_from("<IIII", self.raw, 8)
        self._tbase = hdr_len + type_off
        self._tend = self._tbase + type_len
        self._sbase = hdr_len + str_off
        self.types: list[Type] = [Type(0, K_UNKN, "void")]
        self._by_name: dict[str, list[int]] = {}
        self._parse()
        self._field_cache: dict[tuple[str, str], Field] = {}

    @classmethod
    def from_file(cls, path: str) -> "BTF":
        with open(path, "rb") as f:
            return cls(f.read(), source=path)

    # ------------------------------------------------------------------ parse
    def _str(self, off: int) -> str:
        if off == 0:
            return ""
        i = self._sbase + off
        return self.raw[i:self.raw.index(b"\x00", i)].decode("utf-8", "replace")

    def _parse(self) -> None:
        raw, pos, end = self.raw, self._tbase, self._tend
        unpack = struct.unpack_from
        while pos < end:
            name_off, info, size_or_type = unpack("<III", raw, pos)
            pos += 12
            vlen = info & 0xFFFF
            kind = (info >> 24) & 0x1F
            kflag = bool(info >> 31)
            t = Type(len(self.types), kind, self._str(name_off))
            if kind in (K_STRUCT, K_UNION):
                t.size = size_or_type
                for _ in range(vlen):
                    mn, mt, mo = unpack("<III", raw, pos)
                    pos += 12
                    if kflag:
                        t.members.append(Member(self._str(mn), mt, mo & 0xFFFFFF, mo >> 24))
                    else:
                        t.members.append(Member(self._str(mn), mt, mo, 0))
            elif kind == K_INT:
                t.size = size_or_type
                enc = unpack("<I", raw, pos)[0]
                pos += 4
                t.int_signed = bool((enc >> 24) & 1)
            elif kind == K_ARRAY:
                t.elem, _idx, t.nelems = unpack("<III", raw, pos)
                pos += 12
            elif kind == K_ENUM:
                t.size = size_or_type
                t.enum_values = {}
                for _ in range(vlen):
                    en, ev = unpack("<Ii", raw, pos)
                    pos += 8
                    t.enum_values[self._str(en)] = ev
            elif kind == K_ENUM64:
                t.size = size_or_type
                t.enum_values = {}
                for _ in range(vlen):
                    en, lo, hi = unpack("<III", raw, pos)
                    pos += 12
                    t.enum_values[self._str(en)] = (hi << 32) | lo
            elif kind == K_FUNC_PROTO:
                pos += vlen * 8
            elif kind == K_VAR:
                pos += 4
            elif kind == K_DATASEC:
                pos += vlen * 12
            elif kind == K_DECL_TAG:
                pos += 4
            elif kind == K_FLOAT:
                t.size = size_or_type
            else:  # PTR, TYPEDEF, qualifiers, FWD, FUNC, TYPE_TAG
                t.ref = size_or_type
            self.types.append(t)
            if t.name:
                self._by_name.setdefault(t.name, []).append(t.id)

    # ----------------------------------------------------------------- lookup
    def resolve(self, tid: int) -> Type:
        """Strip typedefs and qualifiers."""
        for _ in range(32):
            t = self.types[tid]
            if t.kind not in _QUALIFIERS:
                return t
            tid = t.ref
        raise ValueError(f"type chain too deep at {tid}")

    def sizeof(self, tid: int) -> int:
        t = self.resolve(tid)
        if t.kind == K_PTR:
            return 8
        if t.kind == K_ARRAY:
            return self.sizeof(t.elem) * t.nelems
        return t.size

    def find_struct(self, name: str) -> Type | None:
        """A complete struct (or union) definition by name, never a forward decl."""
        for tid in self._by_name.get(name, ()):
            t = self.types[tid]
            if t.kind in (K_STRUCT, K_UNION) and (t.members or t.size):
                return t
        return None

    def has_struct(self, name: str) -> bool:
        return self.find_struct(name) is not None

    def struct_size(self, name: str) -> int:
        t = self.find_struct(name)
        if t is None:
            raise KeyError(f"struct {name} not in BTF ({self.source})")
        return t.size

    def enum_value(self, name: str) -> int | None:
        for t in self.types:
            if t.enum_values and name in t.enum_values:
                return t.enum_values[name]
        return None

    def _lookup_member(self, t: Type, name: str, base_bits: int = 0,
                       depth: int = 0) -> tuple[int, Member] | None:
        """Find `name` in t, descending through anonymous structs and unions."""
        if depth > 8:
            return None
        for m in t.members:
            if m.name == name:
                return base_bits + m.bit_offset, m
        for m in t.members:
            if m.name:
                continue
            inner = self.resolve(m.type_id)
            if inner.kind in (K_STRUCT, K_UNION):
                hit = self._lookup_member(inner, name, base_bits + m.bit_offset, depth + 1)
                if hit:
                    return hit
        return None

    def field(self, struct_name: str, path: str) -> Field:
        """Resolve 'f_path.dentry' or 'numbers[0].nr' inside `struct struct_name`.

        Dots descend into EMBEDDED structs only; a pointer on the path is an
        error, because following it needs memory, not types.
        """
        key = (struct_name, path)
        hit = self._field_cache.get(key)
        if hit is not None:
            return hit
        t = self.find_struct(struct_name)
        if t is None:
            raise KeyError(f"struct {struct_name} not in BTF ({self.source})")
        bits = 0
        tid = t.id
        m: Member | None = None
        for part in path.split("."):
            idx = None
            if part.endswith("]") and "[" in part:
                part, _, rest = part.partition("[")
                idx = int(rest[:-1], 0)
            cur = self.resolve(tid)
            if cur.kind not in (K_STRUCT, K_UNION):
                raise KeyError(f"{struct_name}.{path}: '{part}' is not inside a struct")
            found = self._lookup_member(cur, part)
            if found is None:
                raise KeyError(f"{struct_name}.{path}: no member '{part}'")
            off_bits, m = found
            bits += off_bits
            tid = m.type_id
            if idx is not None:
                arr = self.resolve(tid)
                if arr.kind != K_ARRAY:
                    raise KeyError(f"{struct_name}.{path}: '{part}' is not an array")
                bits += idx * self.sizeof(arr.elem) * 8
                tid = arr.elem
        assert m is not None
        size = self.sizeof(tid)
        if m.bitfield_size:
            res = Field(bits // 8, tid, size, bits % 8, m.bitfield_size)
        else:
            res = Field(bits // 8, tid, size)
        self._field_cache[key] = res
        return res

    def has_field(self, struct_name: str, path: str) -> bool:
        try:
            self.field(struct_name, path)
            return True
        except KeyError:
            return False

    def offset(self, struct_name: str, path: str) -> int:
        return self.field(struct_name, path).offset

    def pointee(self, tid: int) -> Type | None:
        t = self.resolve(tid)
        if t.kind != K_PTR:
            return None
        return self.resolve(t.ref) if t.ref else None

    def is_signed(self, tid: int) -> bool:
        t = self.resolve(tid)
        if t.kind == K_INT:
            return t.int_signed
        if t.kind in (K_ENUM, K_ENUM64):
            return True
        return False

    def describe(self, struct_name: str) -> dict:
        t = self.find_struct(struct_name)
        if t is None:
            raise KeyError(struct_name)
        return {"name": struct_name, "size": t.size,
                "members": [{"name": m.name or "<anon>", "offset": m.offset,
                             "bitfield_size": m.bitfield_size} for m in t.members]}
