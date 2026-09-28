"""Inodes in the dump, and the page cache content each one indexes.

Discovery. Every inode embeds its own address_space (i_data) and, for all
ordinary inodes, points at it: `inode->i_mapping == &inode->i_data`. The
address_space points back: `i_data.host == inode`. Two pointers, one fixed
distance from their own address and one equal to the object's base, are
found with the self-relative search (selfptr.py) and cross-checked. Inodes
are accounted objects (`SLAB_ACCOUNT` on ext4, overlay, shmem, proc, sock
inode caches), charged to whoever first looked the file up.

That finds the files the container TOUCHED, not only the ones it still holds
open: a script it downloaded, ran and deleted stays in the inode cache and
the page cache until memory pressure evicts it.

Content. `i_pages` is an XArray from page index to folio. Its nodes come from
radix_tree_node with XA_FLAGS_ACCOUNT on page cache mappings, so they are
charged to the container that populated them. Each leaf is a folio pointer
into the vmemmap: PFN = (ptr - vmemmap_base) / sizeof(struct page), and the
page itself is in the dump if it was charged to the container. Value entries
(bit 0 set) are shadow entries of evicted pages, or swap entries for shmem:
the page is known to have existed and is not resident.

A v2 capture carries struct page for each captured PFN (pagemeta.bin), which
indexes the same content from the other side: page -> mapping, index. The two
are independent paths to the same answer; `filedump` uses the XArray and
reports where pagemeta disagrees.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.kernel import Kernel, is_kptr
from ..core import objects as ko
from .selfptr import self_relative

S_IFMT = 0o170000
FTYPES = {0o140000: "sock", 0o120000: "link", 0o100000: "reg", 0o060000: "blk",
          0o040000: "dir", 0o020000: "chr", 0o010000: "fifo"}

XA_CHUNK_SHIFT = 6
XA_CHUNK_SIZE = 1 << XA_CHUNK_SHIFT
MAX_INDEX = 1 << 40


@dataclass
class Inode:
    va: int
    ino: int
    mode: int
    size: int
    nlink: int | None
    nrpages: int | None
    uid: int | None = None
    mtime: int | None = None
    path: str = ""
    path_complete: bool = False
    dentry: int | None = None
    pages: dict = field(default_factory=dict)   # filled by walk: index -> (pfn|None, status)

    @property
    def ftype(self) -> str:
        return FTYPES.get(self.mode & S_IFMT, "?")

    @property
    def deleted(self) -> bool:
        return self.nlink == 0 and self.ftype in ("reg", "dir", "link")


class InodeScanner:
    def __init__(self, k: Kernel):
        self.k = k
        b = k.btf
        self.off_imap = b.offset("inode", "i_mapping")
        self.off_idata = b.offset("inode", "i_data")
        self.off_host = b.offset("address_space", "host")
        self.stats = {"candidates": 0, "valid": 0}

    def scan(self) -> list[Inode]:
        k = self.k
        delta = self.off_idata - self.off_imap
        out: dict[int, Inode] = {}
        for qpa in self_relative(k.phys, k.dmap.base, delta):
            self.stats["candidates"] += 1
            va = k.dmap.va(qpa) - self.off_imap
            if va in out:
                continue
            host = k.dmap.u64(va + self.off_idata + self.off_host)
            if host != va:
                continue
            ino = read_inode(k, va)
            if ino:
                out[va] = ino
        self.stats["valid"] = len(out)
        return sorted(out.values(), key=lambda x: (x.path == "", x.path, x.ino))


def read_inode(k: Kernel, va: int) -> Inode | None:
    o = k.obj("inode", va)
    if not o:
        return None
    mode = o.int("i_mode")
    ino = o.int("i_ino")
    size = o.int("i_size")
    if mode is None or ino is None or size is None or size < 0 or size > 1 << 50:
        return None
    nlink = o.int("i_nlink") if o.has("i_nlink") else o.int("__i_nlink")
    nr = k.dmap.u64(va + k.off("inode", "i_data") + k.off("address_space", "nrpages"))
    uid = o.int("i_uid.val") if o.has("i_uid.val") else None
    mtime = None
    for f in ("i_mtime.tv_sec", "i_mtime_sec", "__i_mtime.tv_sec"):
        if o.has(f):
            mtime = o.int(f)
            break
    inode = Inode(va=va, ino=ino, mode=mode, size=size, nlink=nlink, nrpages=nr,
                  uid=uid, mtime=mtime)
    first = o.ptr("i_dentry.first") if o.has("i_dentry.first") else None
    if is_kptr(first):
        alias = k.off("dentry", "d_u.d_alias") if k.has("dentry", "d_u.d_alias") \
            else k.off("dentry", "d_alias")
        inode.dentry = first - alias
        inode.path, inode.path_complete = ko.dentry_path(k, inode.dentry)
    return inode


class PageCacheWalker:
    """Walk an inode's i_pages XArray. Yields (index, pfn|None, status)."""

    def __init__(self, k: Kernel):
        self.k = k
        b = k.btf
        self.off_ipages = b.offset("inode", "i_data") + b.offset("address_space", "i_pages")
        self.off_head = b.offset("xarray", "xa_head")
        self.off_shift = b.offset("xa_node", "shift")
        self.off_slots = b.offset("xa_node", "slots")
        img = k.img
        self.vmemmap = img.vmemmap_base
        consts = (img.kernel_meta.get("constants") or {})
        self.sizeof_page = consts.get("sizeof_struct_page") or img.manifest.get("sizeof_page") or 64

    def pfn_of(self, ptr: int) -> int | None:
        if self.vmemmap is None:
            return None
        off = ptr - self.vmemmap
        if off < 0 or off % self.sizeof_page or off // self.sizeof_page > 1 << 40:
            return None
        return off // self.sizeof_page

    def walk(self, inode_va: int, limit_index: int | None = None):
        k = self.k
        head = k.dmap.u64(inode_va + self.off_ipages + self.off_head)
        if head is None:
            yield None, None, "xarray-not-captured"
            return
        if head == 0:
            return
        if not self._is_node(head):
            yield from self._leaf(0, 1, head, None)
            return
        yield from self._node(head - 2, 0, limit_index, depth=0)

    @staticmethod
    def _is_node(e: int) -> bool:
        return (e & 3) == 2 and e > 4096

    def _leaf(self, index: int, span: int, e: int, canon: tuple[int, int] | None):
        if e & 1:
            # value entry: a shadow of an evicted page, or a swap entry (shmem)
            for i in range(span):
                yield index + i, None, "evicted-or-swapped"
            return
        if (e & 3) == 2:
            return                       # retry / zero / sibling handled by caller
        pfn = self.pfn_of(e)
        if pfn is None:
            for i in range(span):
                yield index + i, None, "bad-folio-pointer"
            return
        base_idx, base_pfn = canon if canon else (index, pfn)
        for i in range(span):
            p = base_pfn + (index + i - base_idx)
            st = "ok" if self.k.phys.has_page(p) else "page-not-captured"
            yield index + i, p, st

    def _node(self, node_va: int, base: int, limit, depth: int):
        if depth > 11:
            return
        k = self.k
        raw = k.dmap.read(node_va, self.off_slots + XA_CHUNK_SIZE * 8)
        if raw is None:
            span = 1 << 30
            yield base, None, "xa-node-not-captured"
            return
        shift = raw[self.off_shift]
        if shift % XA_CHUNK_SHIFT or shift > 60:
            yield base, None, "xa-node-invalid"
            return
        slots = [int.from_bytes(raw[self.off_slots + i * 8:self.off_slots + i * 8 + 8], "little")
                 for i in range(XA_CHUNK_SIZE)]
        span = 1 << shift
        for i, e in enumerate(slots):
            if not e:
                continue
            idx = base + (i << shift)
            if limit is not None and idx > limit:
                break
            if self._is_node(e) and shift > 0:
                yield from self._node(e - 2, idx, limit, depth + 1)
            elif (e & 3) == 2 and (e >> 2) < XA_CHUNK_SIZE - 1:
                # sibling: part of a multi-index entry that starts at slot e>>2
                j = e >> 2
                head = slots[j]
                if head and not head & 3:
                    pfn = self.pfn_of(head)
                    if pfn is not None:
                        yield from self._leaf(idx, span, head, (base + (j << shift), pfn))
            elif (e & 3) == 2:
                continue                  # retry or zero entry
            else:
                yield from self._leaf(idx, span, e, None)


def pagemeta_index(k: Kernel) -> dict[int, dict[int, int]]:
    """v2 only: inode va -> {page index: pfn}, from struct page.mapping/index.

    The independent path to a file's captured pages: it needs neither the
    XArray nodes nor the inode itself to be in the dump.
    """
    pm = k.img.pagemeta
    if pm is None:
        return {}
    b = k.btf
    off_map = b.offset("page", "mapping")
    off_idx = b.offset("page", "index") if b.has_field("page", "index") \
        else b.offset("page", "__folio_index")
    off_idata = b.offset("inode", "i_data")
    out: dict[int, dict[int, int]] = {}
    for pfn in pm.pfns("regular"):
        raw = pm.struct_page(pfn)
        mapping = int.from_bytes(raw[off_map:off_map + 8], "little")
        if not is_kptr(mapping) or mapping & 3:
            continue
        idx = int.from_bytes(raw[off_idx:off_idx + 8], "little")
        out.setdefault(mapping - off_idata, {})[idx] = pfn
    return out
