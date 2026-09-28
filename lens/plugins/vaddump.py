"""vol3 `linux.proc.Maps --dump` / Windows vaddump equivalent: one file per VMA.

Same engine as procdump; kept under the name analysts coming from Volatility
look for. `--address` narrows it to the VMA(s) holding an address.
"""
from __future__ import annotations

from . import procdump

NAME = "vaddump"
HELP = "dump VMAs of a process to files (vol3 linux.proc.Maps --dump); --address to pick one"


def add_args(ap) -> None:
    procdump.add_args(ap)


def run(s, args):
    res = procdump.run(s, args)
    res.title = "vaddump"
    return res
