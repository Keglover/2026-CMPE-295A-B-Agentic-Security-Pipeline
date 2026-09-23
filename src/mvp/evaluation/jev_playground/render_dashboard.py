"""Render a single-file HTML dashboard from eval results."""

from __future__ import annotations

import html
from typing import Any


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.2f}"
    return html.escape(str(value))


def render_dashboard(payload: dict[str, Any]) -> str:
    """
    Build a standalone HTML page from a run payload.

    Args:
        payload: Output of run_evals.build_report().

    Returns:
        str: Full HTML document.
    """
    rows = payload.get("cases", [])
    noul_ids: list[str] = payload.get("noul_ids", [])
    matched = sum(1 for row in rows if row.get("match") is True)
    total = len(rows)
    counts = {"pass": 0, "review": 0, "block": 0, "error": 0}
    for row in rows:
        key = row.get("decision") if row.get("decision") in counts else "error"
        counts[key] += 1

    header_extra = "".join(f"<th>{html.escape(qid)}</th>" for qid in noul_ids)
    body = []
    for row in rows:
        decision = row.get("decision", "error")
        match = row.get("match")
        match_cell = "yes" if match is True else ("no" if match is False else "—")
        noul_cells = "".join(
            f"<td>{_fmt(row.get('nouls', {}).get(qid))}</td>" for qid in noul_ids
        )
        body.append(
            "<tr class='{cls}'>"
            "<td>{cid}</td><td>{exp}</td><td>{dec}</td><td>{match}</td>"
            "<td>{cat}</td><td>{sev}</td><td>{trig}</td>{nouls}"
            "<td class='clip'>{note}</td>"
            "</tr>".format(
                cls=html.escape(str(decision)),
                cid=_fmt(row.get("id")),
                exp=_fmt(row.get("expect_decision")),
                dec=_fmt(decision),
                match=match_cell,
                cat=_fmt(row.get("primary_category")),
                sev=_fmt(row.get("severity")),
                trig=_fmt(row.get("trigger")),
                nouls=noul_cells,
                note=_fmt(row.get("expect")),
            )
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Jev eval dashboard</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 24px;
           background: #111; color: #eee; }}
    h1 {{ font-size: 20px; margin: 0 0 8px; }}
    .meta {{ color: #aaa; font-size: 13px; margin-bottom: 20px; }}
    .stats {{ display: flex; gap: 12px; margin-bottom: 20px; }}
    .stat {{ background: #1c1c1c; padding: 12px 16px; min-width: 90px; }}
    .stat b {{ display: block; font-size: 22px; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #333; }}
    th {{ color: #aaa; font-weight: 600; }}
    tr.pass td:nth-child(3) {{ color: #7dcea0; }}
    tr.review td:nth-child(3) {{ color: #f4d03f; }}
    tr.block td:nth-child(3) {{ color: #e74c3c; }}
    tr.error td:nth-child(3) {{ color: #bb8fce; }}
    .clip {{ max-width: 280px; overflow: hidden; text-overflow: ellipsis;
             white-space: nowrap; color: #999; }}
  </style>
</head>
<body>
  <h1>Jev eval dashboard</h1>
  <div class="meta">
    Model {html.escape(str(payload.get("model", "")))} ·
    {html.escape(str(payload.get("questions_file", "")))} ·
    cached {payload.get("cached", 0)} / live {payload.get("live", 0)}
  </div>
  <div class="stats">
    <div class="stat"><b>{matched}/{total}</b>expect match</div>
    <div class="stat"><b>{counts["pass"]}</b>pass</div>
    <div class="stat"><b>{counts["review"]}</b>review</div>
    <div class="stat"><b>{counts["block"]}</b>block</div>
    <div class="stat"><b>{counts["error"]}</b>error</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>id</th><th>expect</th><th>got</th><th>match</th>
        <th>category</th><th>severity</th><th>trigger</th>
        {header_extra}<th>note</th>
      </tr>
    </thead>
    <tbody>
      {"".join(body)}
    </tbody>
  </table>
</body>
</html>
"""
