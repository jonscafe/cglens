"""Plugin registry. Each plugin module defines NAME, HELP, add_args(ap), run(s, args)."""
from __future__ import annotations

import importlib

ORDER = ["info", "psscan", "pslist", "pstree", "maps", "cmdline", "envars",
         "lsof", "sockstat", "procdump", "vaddump", "elfs", "malfind", "files",
         "filedump", "grep"]


def load(name: str):
    if name not in ORDER:
        raise KeyError(name)
    return importlib.import_module(f"{__name__}.{name}")


def all_plugins():
    return [load(n) for n in ORDER]
