"""Find qwords that point a fixed distance from their own address.

Many kernel objects hold pointers into themselves: an empty list_head points
at itself (distance 0), an inode's i_mapping points at its own embedded i_data
(distance = offsetof(i_data) - offsetof(i_mapping)). With page_offset_base
known, the address of every qword in the dump is known too, so "value ==
own address + delta" can be tested without knowing where objects start.

Testing every qword in Python is slow (tens of millions of iterations). The
search here is done at C speed instead: within one 64 KiB aligned virtual
region, every qword of the form own+delta shares its upper six bytes with one
of at most two values, so `bytes.find` on that 6 byte pattern returns only
the handful of candidates worth an exact check.
"""
from __future__ import annotations

REGION = 0x10000


def self_relative(phys, base: int, delta: int):
    """Physical address of every 8-aligned qword q with u64(q) == base + q + delta."""
    buf = phys.buf
    for pa, fo, n in phys.ranges:
        if fo % 8:
            continue
        off = 0
        while off < n:
            va0 = base + pa + off
            end = min(n, off + (REGION - (va0 & (REGION - 1))))
            first, last = va0 + delta, base + pa + end - 8 + delta
            pats = {(first >> 16).to_bytes(6, "little"), (last >> 16).to_bytes(6, "little")}
            lo, hi = fo + off, fo + end
            for pat in pats:
                i = buf.find(pat, lo + 2, hi)
                while i != -1:
                    q = i - 2
                    if (q - fo) % 8 == 0 and q + 8 <= hi:
                        v = int.from_bytes(buf[q:q + 8], "little")
                        own = base + pa + (q - fo)
                        if v == own + delta:
                            yield pa + (q - fo)
                    i = buf.find(pat, i + 1, hi)
            off = end
