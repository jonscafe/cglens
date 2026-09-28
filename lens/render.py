"""Plugin results and their text / JSON rendering."""
from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Result:
    title: str
    columns: list[str]
    rows: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"title": self.title, "columns": self.columns, "rows": self.rows,
                "notes": self.notes, "meta": self.meta}


def _cell(v) -> str:
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (list, tuple)):
        return ",".join(_cell(x) for x in v)
    return str(v)


def text(res: Result, max_width: int = 80) -> str:
    out = [f"== {res.title} =="]
    # columns holding multi-line values (hexdumps) are printed as blocks below
    blocks = [c for c in res.columns if any("\n" in str(r.get(c) or "") for r in res.rows)]
    cols = [c for c in res.columns if c not in blocks]
    if blocks:
        res = Result(res.title, cols, res.rows, res.notes, res.meta)
    if res.columns and res.rows:
        cells = [[_cell(r.get(c)) for c in res.columns] for r in res.rows]
        widths = [len(c) for c in res.columns]
        for row in cells:
            for i, v in enumerate(row):
                widths[i] = min(max(widths[i], len(v)), max_width)
        fmt = "  ".join("{:<%d}" % w for w in widths)
        out.append(fmt.format(*res.columns).rstrip())
        for row in cells:
            out.append(fmt.format(*[v if len(v) <= max_width else v[:max_width - 1] + "…"
                                    for v in row]).rstrip())
    elif res.columns:
        out.append("(no rows)")
    for i, r in enumerate(res.rows):
        for c in blocks:
            out.append(f"--- row {i} {c}:")
            out.append(str(r.get(c)))
    for k, v in res.meta.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        out.append(f"{k}: {v}")
    for n in res.notes:
        out.append(f"note: {n}")
    return "\n".join(out)


def as_json(res: Result) -> str:
    return json.dumps(res.to_json(), indent=2, ensure_ascii=False, default=str)
