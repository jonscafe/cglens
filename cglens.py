#!/usr/bin/env python3
"""cglens: offline analysis of cglime container memory captures.

    python3 cglens.py <plugin> <capture> [options]

<capture> is a .cglime bundle or a .lime file with its sidecars beside it.
Run a plugin with -h for its options. No dependencies, Python 3.10+.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lens import __version__  # noqa: E402
from lens import plugins  # noqa: E402
from lens.core.image import Image, ImageError  # noqa: E402
from lens.render import as_json, text  # noqa: E402
from lens.session import Session  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="cglens", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"cglens {__version__}")
    sub = ap.add_subparsers(dest="plugin", metavar="<plugin>")
    for mod in plugins.all_plugins():
        p = sub.add_parser(mod.NAME, help=mod.HELP, description=mod.HELP)
        p.add_argument("capture", help=".cglime bundle or .lime dump")
        p.add_argument("--btf", help="BTF blob for the captured kernel (pre-v2 captures)")
        p.add_argument("--btf-dir", help="directory of <kernel_release>.btf files")
        p.add_argument("--no-sidecars", action="store_true",
                       help="ignore v2 sidecars (ablation: analyse as a pre-v2 capture)")
        p.add_argument("--json", action="store_true", help="JSON output")
        p.add_argument("-o", "--output", help="write output to this file")
        mod.add_args(p)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    # accept `cglens <capture> <plugin>` too: swap when the first word is not a
    # plugin but the second is
    names = plugins.ORDER
    if len(argv) >= 2 and argv[0] not in names and argv[1] in names \
            and not argv[0].startswith("-"):
        argv[0], argv[1] = argv[1], argv[0]
    args = ap.parse_args(argv)
    if not args.plugin:
        ap.print_help()
        return 2
    mod = plugins.load(args.plugin)
    t0 = time.time()
    try:
        img = Image(args.capture, btf=args.btf, btf_dir=args.btf_dir,
                    use_sidecars=not args.no_sidecars)
    except ImageError as e:
        print(f"cglens: {e}", file=sys.stderr)
        return 1
    s = Session(img)
    try:
        res = mod.run(s, args)
    except ImageError as e:
        print(f"cglens: {e}", file=sys.stderr)
        return 1
    res.meta.setdefault("seconds", round(time.time() - t0, 2))
    if img.btf_source and img.btf_source.startswith("analyst"):
        res.notes.append(img.btf_note)
    out = as_json(res) if args.json else text(res)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out + "\n")
    else:
        print(out)
    img.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
