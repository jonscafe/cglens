#!/usr/bin/env python3
"""The workload inside the published sample capture.

Everything in it is synthetic and planted on purpose, so each plugin has
something known to find: three named threads, a child process, an open file, a
deleted file still held open, a file written and closed (reachable only through
its inode and page cache), two memfds (one holding a shared library that is then
loaded from it, as a fileless implant would), an RWX mapping, TCP, UDP and Unix
sockets, and a pipe. Every planted value carries the marker, CGLENS-SAMPLE by
default, and the "secrets" are that marker and nothing else.

make_sample.sh copies this file into a python:3.12-slim container and runs it.
It is the same workload cglens is validated against on live hosts.
"""
import ctypes
import glob
import hashlib
import mmap
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

MARK = sys.argv[sys.argv.index("--marker") + 1] if "--marker" in sys.argv else "CGLENS-SAMPLE"
libc = ctypes.CDLL(None)
PR_SET_NAME = 15


def worker(name, evt):
    libc.prctl(PR_SET_NAME, name.encode(), 0, 0, 0)
    blob = (f"{MARK}-HEAP-{name}-" * 64).encode()   # heap marker, per thread
    evt.wait()
    return blob


def det_bytes(tag: str, n: int) -> bytes:
    """Deterministic, incompressible content with a marker every 512 bytes."""
    out = bytearray()
    h = hashlib.sha256(tag.encode()).digest()
    while len(out) < n:
        h = hashlib.sha256(h).digest()
        out += h
        if len(out) % 512 < 32:
            out += f"{MARK}-{tag}".encode()
    return bytes(out[:n])


evt = threading.Event()
threads = [threading.Thread(target=worker, args=(f"cgl-worker-{i}", evt), daemon=True)
           for i in range(3)]
for t in threads:
    t.start()

keep = []
# 1. an open file, and an open file that was then deleted (content spans 3 pages)
f1 = open("/tmp/cglens_open.txt", "w+")
f1.write(MARK + "-FILE\n"); f1.flush(); keep.append(f1)
f2 = open("/tmp/cglens_deleted.txt", "wb+")
f2.write(det_bytes("DELETED", 9000)); f2.flush()
os.unlink("/tmp/cglens_deleted.txt"); keep.append(f2)
# 2. a file written and CLOSED: reachable only through the inode and page cache
with open("/tmp/cglens_known.bin", "wb") as f:
    f.write(det_bytes("KNOWNFILE", 3 * 4096 + 123))
# 3. memfds: a plain one, and one holding a shared object that is then loaded
mfd = os.memfd_create("cglens-memfd")
os.write(mfd, (MARK + "-MEMFD\n").encode() * 100)
so_src = sorted(glob.glob("/usr/local/lib/python3.12/lib-dynload/_bisect*.so"))[0]
lfd = os.memfd_create("cglens-lib")
with open(so_src, "rb") as src:
    os.write(lfd, src.read())
lib = ctypes.CDLL(f"/proc/self/fd/{lfd}")        # fileless load, as an implant would
# 4. anonymous read+write+exec memory with a marker
PROT_RWX = mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
rwx = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, prot=PROT_RWX)
rwx.write(b"\x90" * 32 + (MARK + "-RWX").encode() + b"\xc3")
keep.append(rwx)
# 5. sockets: TCP listener with one established pair, UDP, unix path and abstract
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 8765)); srv.listen(4); keep.append(srv)
cli = socket.create_connection(("127.0.0.1", 8765)); acc, _ = srv.accept()
keep += [cli, acc]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 9876))
keep.append(udp)
ux = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); ux.bind("/tmp/cglens.sock")
ux.listen(1); keep.append(ux)
uab = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); uab.bind("\0cglens-abs")
keep.append(uab)
r, w = os.pipe()
secret = bytearray((MARK + "-SECRET-" + "A" * 40).encode())   # live heap object
child = subprocess.Popen(["sleep", "3600"])
time.sleep(1)
print("READY", os.getpid(), child.pid, lfd, so_src, flush=True)
while True:
    time.sleep(3600)
