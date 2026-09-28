"""Sockets of container processes (vol3 linux.sockstat), plus a slab sweep.

From each socket fd: file->private_data is the struct socket, socket->sk the
struct sock, whose __sk_common holds family, state, addresses and ports.
Socket objects come from protocol caches (TCP, UDP, UNIX, ...) that are
memcg accounted, so the container's sockets are in its dump.

`--scan` also sweeps those caches using a v2 capture's slab map, which finds
sockets no fd points at any more: closed, orphaned, or held only by the
kernel. Per network namespace kernel sockets (ICMPv6/NDISC control sockets,
for example) are charged to the container that created the namespace and show
up here too.
"""
from __future__ import annotations

import ipaddress

from ..core.kernel import is_kptr
from ..render import Result
from .lsof import S_IFMT

NAME = "sockstat"
HELP = "sockets per process: family, protocol, local/remote address, state (unix paths too)"

FAMILIES = {1: "unix", 2: "inet", 10: "inet6", 16: "netlink", 17: "packet"}
TYPES = {1: "stream", 2: "dgram", 3: "raw", 5: "seqpacket"}
PROTOS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6", 255: "raw"}
TCP_STATES = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
              5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
              10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"}
SOCK_CACHES = {"TCP", "TCPv6", "UDP", "UDPv6", "UNIX", "UNIX-STREAM", "RAW", "RAWv6",
               "PING", "PINGv6", "UDP-Lite", "UDPLITEv6"}


def add_args(ap) -> None:
    ap.add_argument("-p", "--pid", type=int, action="append")
    ap.add_argument("--all-tasks", action="store_true")
    ap.add_argument("--scan", action="store_true",
                    help="also sweep socket caches (v2 slab map) for sockets without an fd")


def _be16(x: int) -> int:
    return ((x & 0xFF) << 8) | (x >> 8)


def describe_sock(k, sk_va: int) -> dict | None:
    sk = k.obj("sock", sk_va)
    if not sk:
        return None
    fam = sk.int("__sk_common.skc_family")
    if fam not in FAMILIES:
        return None
    st = sk.int("__sk_common.skc_state")
    styp = sk.int("sk_type")
    proto = sk.int("sk_protocol")
    d = {"family": FAMILIES[fam], "type": TYPES.get(styp, str(styp)),
         "proto": PROTOS.get(proto, str(proto)) if fam in (2, 10) else "",
         "state": "", "local": "", "remote": "", "sock": hex(sk_va)}
    if fam in (2, 10) and styp == 3:
        # raw sockets keep the IP protocol number where a port would be
        d["proto"] = f"raw/{PROTOS.get(proto, proto)}"
        d["state"] = ""
        d["local"] = "*"
    elif fam in (2, 10):
        lport = sk.int("__sk_common.skc_num") or 0
        rport = _be16(sk.int("__sk_common.skc_dport") or 0)
        if fam == 2:
            la = ipaddress.IPv4Address(sk.bytes("__sk_common.skc_rcv_saddr", 4))
            ra = ipaddress.IPv4Address(sk.bytes("__sk_common.skc_daddr", 4))
            d["local"], d["remote"] = f"{la}:{lport}", f"{ra}:{rport}"
        else:
            la = ipaddress.IPv6Address(sk.bytes("__sk_common.skc_v6_rcv_saddr", 16))
            ra = ipaddress.IPv6Address(sk.bytes("__sk_common.skc_v6_daddr", 16))
            d["local"], d["remote"] = f"[{la}]:{lport}", f"[{ra}]:{rport}"
        if d["proto"] == "tcp":
            d["state"] = TCP_STATES.get(st, str(st))
        elif d["proto"] == "udp":
            d["state"] = "ESTABLISHED" if st == 1 else "UNCONN"
    elif fam == 1 and k.has("unix_sock", "addr"):
        u = k.obj("unix_sock", sk_va)
        addr = u.ptr("addr")
        name = unix_name(k, addr)
        if name is None and is_kptr(addr):
            # unix_address is kmalloc'd without accounting, so it is usually
            # not in the dump. A path socket still has its dentry (unix_sock.path),
            # which is accounted; an abstract name exists only in unix_address.
            dva = u.ptr("path.dentry") if u.has("path.dentry") else None
            if is_kptr(dva):
                from ..core.objects import dentry_path
                name = dentry_path(k, dva)[0]
            else:
                name = "<abstract or unnamed: unix_address not captured>"
        d["local"] = name or ""
        peer = u.ptr("peer") if u.has("peer") else None
        if is_kptr(peer):
            pu = k.obj("unix_sock", peer)
            d["remote"] = (unix_name(k, pu.ptr("addr")) if pu else None) or f"peer {peer:#x}"
        d["state"] = {1: "ESTABLISHED", 7: "CLOSE", 10: "LISTEN"}.get(st, str(st))
    return d


def unix_name(k, addr_va: int | None) -> str | None:
    if not is_kptr(addr_va):
        return None
    a = k.obj("unix_address", addr_va)
    if not a:
        return None
    ln = a.int("len")
    if not ln or ln <= 2 or ln > 110:
        return None
    raw = k.dmap.read(a.addr("name") + 2, ln - 2)
    if raw is None:
        return None
    if raw[:1] == b"\x00":
        return "@" + raw[1:].split(b"\x00")[0].decode("utf-8", "replace")
    return raw.split(b"\x00")[0].decode("utf-8", "replace")


def fd_sockets(s, p):
    k = s.k
    t = k.obj("task_struct", p.va)
    files = t.deref("files", "files_struct") if t.has("files") else None
    fdt = files.deref("fdt", "fdtable") if files else None
    if not fdt:
        return
    n = min(fdt.int("max_fds") or 0, 65536)
    arr = fdt.ptr("fd")
    raw = k.dmap.read(arr, n * 8) if is_kptr(arr) and n else None
    if raw is None:
        return
    for fd in range(n):
        fva = int.from_bytes(raw[fd * 8:fd * 8 + 8], "little")
        if not is_kptr(fva):
            continue
        f = k.obj("file", fva)
        if not f:
            continue
        ino = k.obj("inode", f.ptr("f_inode")) if f.has("f_inode") else None
        if not ino or ((ino.int("i_mode") or 0) & S_IFMT) != 0o140000:
            continue
        sock = k.obj("socket", f.ptr("private_data"))
        sk = sock.ptr("sk") if sock else None
        yield fd, ino.int("i_ino"), sk


def run(s, args) -> Result:
    k = s.k
    rows, notes = [], []
    seen: set[int] = set()
    for p in s.select(args.pid, args.all_tasks):
        for fd, ino, sk in fd_sockets(s, p):
            d = describe_sock(k, sk) if is_kptr(sk) else None
            if is_kptr(sk):
                seen.add(sk)
            rows.append({"pid": p.tgid, "comm": p.comm, "fd": fd, "inode": ino,
                         **(d or {"family": "?", "local": "<struct sock not captured>"})})
    if args.scan:
        sm = s.img.slabmap
        if sm is None:
            notes.append("--scan needs a v2 capture (slab map with cache names)")
        else:
            for va, cache, owned in sm.objects(SOCK_CACHES):
                if va in seen or not owned:
                    continue
                d = describe_sock(k, va)
                if d:
                    rows.append({"pid": None, "comm": f"<no fd: {cache}>", "fd": None,
                                 "inode": None, **d})
    return Result("sockstat", ["pid", "comm", "fd", "inode", "family", "proto", "type",
                               "state", "local", "remote", "sock"], rows, notes,
                  {"sockets": len(rows)})
