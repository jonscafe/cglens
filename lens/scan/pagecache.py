"""From a captured page back to the file it caches, without its struct file.

A file-backed VMA names its file through vm_file. On overlayfs from 6.6 that
struct file is the internal backing file, kzalloc'd without memcg accounting,
so it is never in a container dump: every mapped library shows as "file not
captured" even though its pages are there.

The page itself still knows its file. struct page (recorded in a v2 capture's
pagemeta.bin) holds `mapping`, the address_space embedded in the file's inode,
and `index`, the page's offset in the file. The inode links to its dentries
through i_dentry, and the dentry chain gives the name. Inodes and dentries are
accounted objects, charged to whoever first looked the file up; for files the
container opened first, that is the container, and they are in the dump.

    PTE -> PFN -> struct page.mapping -> inode (container_of i_data)
        -> i_dentry.first -> dentry (container_of d_alias) -> d_parent chain

The same walk identifies the file behind ANY captured page cache page, mapped
or not, which is what page cache file carving builds on.
"""
from __future__ import annotations

from ..core.kernel import Kernel, is_kptr
from ..core import objects as ko

PAGE_MAPPING_ANON = 0x1
PAGE_MAPPING_MOVABLE = 0x2
PAGE_MAPPING_FLAGS = 0x3


def _first_field(btf, struct, names):
    for n in names:
        if btf.has_field(struct, n):
            return btf.offset(struct, n)
    return None


class PageCache:
    def __init__(self, k: Kernel):
        self.k = k
        self.pm = k.img.pagemeta
        b = k.btf
        self.off_mapping = _first_field(b, "page", ["mapping"])
        self.off_index = _first_field(b, "page", ["index", "__folio_index"])
        self.off_compound = _first_field(b, "page", ["compound_head", "compound_info"])
        self.off_i_data = b.offset("inode", "i_data")
        self.off_alias = _first_field(b, "dentry", ["d_u.d_alias", "d_alias"])
        self.available = bool(self.pm) and None not in (self.off_mapping, self.off_alias)
        self._inode_path: dict[int, tuple[str, bool, int | None]] = {}

    def _u64(self, raw: bytes, off: int | None) -> int | None:
        if off is None or raw is None:
            return None
        return int.from_bytes(raw[off:off + 8], "little")

    def page_file(self, pfn: int) -> tuple[int, int | None] | None:
        """(inode virtual address, page index in file) for a page cache page."""
        raw = self.pm.struct_page(pfn)
        if raw is None:
            return None
        ch = self._u64(raw, self.off_compound)
        if ch is not None and ch & 1:
            # a tail: mapping and index live on the head. Absolute encoding
            # (head pointer | 1) only; 7.1's relative encoding is left alone
            # rather than guessed.
            head = self.pm.pfn_of_page_ptr(ch & ~1)
            raw = self.pm.struct_page(head) if head is not None else None
            if raw is None:
                return None
        mapping = self._u64(raw, self.off_mapping)
        if not is_kptr(mapping) or mapping & PAGE_MAPPING_FLAGS:
            return None                      # anonymous, movable, or unset
        inode_va = mapping - self.off_i_data
        ino = self.k.obj("inode", inode_va)
        if not ino or ino.ptr("i_mapping") != mapping:
            return None                      # inode not captured, or not an inode's own mapping
        return inode_va, self._u64(raw, self.off_index)

    def inode_path(self, inode_va: int) -> tuple[str, bool, int | None]:
        hit = self._inode_path.get(inode_va)
        if hit:
            return hit
        ino = self.k.obj("inode", inode_va)
        first = ino.ptr("i_dentry.first") if ino.has("i_dentry.first") else ino.ptr("i_dentry")
        if is_kptr(first):
            path, complete = ko.dentry_path(self.k, first - self.off_alias)
        else:
            path, complete = f"<inode {ino.int('i_ino')} without a captured dentry>", False
        hit = (path, complete, ino.int("i_ino"))
        self._inode_path[inode_va] = hit
        return hit

    def vma_file(self, aspace, start: int, end: int, max_probe: int = 64):
        """Identify the file behind a VMA from the first captured page it maps."""
        if not self.available or aspace is None:
            return None
        va = start
        probes = 0
        while va < end and probes < max_probe:
            t = aspace.translate(va)
            probes += 1
            if t.ok:
                hit = self.page_file(t.pa >> 12)
                if hit:
                    path, complete, ino = self.inode_path(hit[0])
                    return {"path": path, "complete": complete, "inode": ino,
                            "inode_va": hit[0]}
            va += 4096
        return None
