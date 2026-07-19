# Visual HTML Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stdlib-only `src/generate_report.py` that turns alert JSON logs into one self-contained `logs/report.html` showing each detection with the evidence that fired it.

**Architecture:** One new script alongside `summarize_logs.py`, reusing its `load_alerts`/`source_key`. Pure string-building renderers (one function per page section), inline CSS + inline SVG, no server. Spec: `docs/superpowers/specs/2026-07-19-visual-report-design.md`.

**Tech Stack:** Python 3.12, stdlib only (`argparse`, `html`, `collections`, `pathlib`). Tests: pytest (already in `.venv`).

## Global Constraints

- **No new dependencies.** Report code and its tests must not import scapy or anything outside stdlib + `summarize_logs`.
- **Repo conventions:** every file starts `from __future__ import annotations`; full type hints; CLI scripts use `argparse` with `run()` + `parse_args()` + `__main__` block.
- **Alert schema is fixed:** top-level `timestamp`/`type`/`details`; source is `details.source_ip` or `details.ip`. Types: `possible_port_scan` (`unique_ports_in_window`, `window_seconds`), `dns_burst_anomaly` (`requests_in_window`, `window_seconds`), `possible_arp_spoofing` (`ip`, `known_mac`, `observed_mac`).
- **Never crash on bad input:** unknown alert type or missing detail key → render generic/partial card, no exception.
- **Every value from a log is HTML-escaped** via `html.escape` before insertion.
- **Self-contained output:** no external URLs, no `<link>`, no `<script>` in generated HTML.
- Run tests from repo root: `.venv/bin/python -m pytest tests/test_generate_report.py -v` (conftest adds `src/` to `sys.path`).
- Commit after each task (messages below). Do not push.

---

### Task 1: Core report — document skeleton, summary tiles, timeline, escaping, empty state

**Files:**

- Create: `src/generate_report.py`
- Create: `tests/test_generate_report.py`

**Interfaces:**

- Consumes: `summarize_logs.source_key(alert: dict) -> str` (existing).
- Produces: `build_report(alerts: List[dict], source_names: List[str]) -> str` (full HTML document); `evidence_summary(alert: dict) -> str`; `esc(value: object) -> str`. Task 2 inserts a cards section into `build_report`; Task 3 wraps it in a CLI.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_generate_report.py`:

```python
from __future__ import annotations

import json
from pathlib import Path

from generate_report import build_report

SAMPLE_ALERTS = [
    {
        "timestamp": "2026-07-18T12:00:00+00:00",
        "type": "possible_port_scan",
        "details": {
            "source_ip": "192.168.8.60",
            "unique_ports_in_window": 8,
            "window_seconds": 20,
        },
    },
    {
        "timestamp": "2026-07-18T12:00:01+00:00",
        "type": "dns_burst_anomaly",
        "details": {
            "source_ip": "192.168.8.50",
            "requests_in_window": 10,
            "window_seconds": 20,
        },
    },
    {
        "timestamp": "2026-07-18T12:00:02+00:00",
        "type": "possible_arp_spoofing",
        "details": {
            "ip": "192.168.8.10",
            "known_mac": "aa:bb:cc:dd:ee:01",
            "observed_mac": "aa:bb:cc:dd:ee:02",
        },
    },
]


def test_report_contains_sources_and_evidence() -> None:
    page = build_report(SAMPLE_ALERTS, ["pcap_alerts.json"])
    assert "pcap_alerts.json" in page
    assert "192.168.8.60" in page
    assert "192.168.8.50" in page
    assert "192.168.8.10" in page
    # evidence values surface in the timeline
    assert "8 unique ports" in page
    assert "10 DNS requests" in page
    assert "aa:bb:cc:dd:ee:01" in page
    assert "aa:bb:cc:dd:ee:02" in page


def test_report_counts_by_type_and_source() -> None:
    page = build_report(SAMPLE_ALERTS, ["run.json"])
    assert "possible_port_scan" in page
    assert "dns_burst_anomaly" in page
    assert "possible_arp_spoofing" in page
    assert ">3<" in page  # total-alerts tile


def test_empty_log_renders_note_not_crash() -> None:
    page = build_report([], ["empty.json"])
    assert "No alerts" in page
    assert ">0<" in page


def test_output_is_self_contained() -> None:
    page = build_report(SAMPLE_ALERTS, ["run.json"])
    assert 'src="http' not in page
    assert 'href="http' not in page
    assert "<link" not in page
    assert "<script" not in page


def test_log_values_are_html_escaped() -> None:
    hostile = [
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "type": "<script>alert(1)</script>",
            "details": {"source_ip": "<img src=x>"},
        }
    ]
    page = build_report(hostile, ["hostile.json"])
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "<img src=x>" not in page


def test_unknown_type_and_missing_keys_render_generic() -> None:
    weird = [
        {"timestamp": "2026-07-18T12:00:00+00:00", "type": "novel_thing", "details": {"foo": 1}},
        {"type": "possible_port_scan", "details": {}},
        {},
    ]
    page = build_report(weird, ["weird.json"])
    assert "novel_thing" in page
    assert "foo" in page
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_generate_report.py -v`
Expected: collection error — `ModuleNotFoundError: No module named 'generate_report'`

- [ ] **Step 3: Write the implementation**

Create `src/generate_report.py`:

```python
from __future__ import annotations

import html
from collections import Counter
from typing import List

from summarize_logs import source_key

CSS = """
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#222}
header p{color:#666}
.tiles{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.tile{border:1px solid #ddd;border-radius:8px;padding:1rem;flex:1;min-width:12rem}
.tile h2{margin:0;font-size:2rem}
.tile ul{margin:.5rem 0 0;padding-left:1.2rem}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}
.empty{color:#666;font-style:italic}
code{background:#f4f4f6;padding:0 .25rem;border-radius:4px}
"""


def esc(value: object) -> str:
    return html.escape(str(value))


def evidence_summary(alert: dict) -> str:
    details = alert.get("details", {})
    alert_type = alert.get("type", "unknown")
    if alert_type == "possible_port_scan":
        return (
            f"{details.get('unique_ports_in_window', '?')} unique ports "
            f"in {details.get('window_seconds', '?')}s window"
        )
    if alert_type == "dns_burst_anomaly":
        return (
            f"{details.get('requests_in_window', '?')} DNS requests "
            f"in {details.get('window_seconds', '?')}s window"
        )
    if alert_type == "possible_arp_spoofing":
        return (
            f"{details.get('ip', '?')} changed "
            f"{details.get('known_mac', '?')} -> {details.get('observed_mac', '?')}"
        )
    return ", ".join(f"{key}={value}" for key, value in details.items()) or "no details"


def render_summary(alerts: List[dict]) -> str:
    by_type = Counter(alert.get("type", "unknown") for alert in alerts)
    by_source = Counter(source_key(alert) for alert in alerts)
    type_items = "".join(
        f"<li><code>{esc(alert_type)}</code>: {count}</li>"
        for alert_type, count in sorted(by_type.items())
    )
    source_items = "".join(
        f"<li><code>{esc(source)}</code>: {count}</li>"
        for source, count in sorted(by_source.items(), key=lambda item: (-item[1], item[0]))
    )
    return (
        '<section class="tiles">'
        f'<div class="tile"><h2>{len(alerts)}</h2><p>total alerts</p></div>'
        f'<div class="tile"><h3>By type</h3><ul>{type_items or "<li>(none)</li>"}</ul></div>'
        f'<div class="tile"><h3>By source</h3><ul>{source_items or "<li>(none)</li>"}</ul></div>'
        "</section>"
    )


def render_timeline(alerts: List[dict]) -> str:
    if not alerts:
        return ""
    rows = "".join(
        f"<tr><td>{esc(alert.get('timestamp', '?'))}</td>"
        f"<td><code>{esc(alert.get('type', 'unknown'))}</code></td>"
        f"<td>{esc(source_key(alert))}</td>"
        f"<td>{esc(evidence_summary(alert))}</td></tr>"
        for alert in sorted(alerts, key=lambda alert: str(alert.get("timestamp", "")))
    )
    return (
        "<section><h2>Timeline</h2><table>"
        "<thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
    )


def build_report(alerts: List[dict], source_names: List[str]) -> str:
    sources = ", ".join(esc(name) for name in source_names)
    if alerts:
        body = render_summary(alerts) + render_timeline(alerts)
    else:
        body = render_summary(alerts) + '<p class="empty">No alerts in the provided logs.</p>'
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        "<title>Network Anomaly Report</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body>\n"
        "<header><h1>Network Anomaly Monitor &mdash; Alert Report</h1>"
        f"<p>Generated from: {sources}</p></header>\n"
        f"{body}\n</body>\n</html>\n"
    )
```

Notes for the implementer:

- ISO-8601 UTC timestamps sort correctly as strings; no datetime parsing needed.
- `render_summary`/`render_timeline` never index into `details` directly — always `.get` with a fallback, so the missing-keys test passes.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_generate_report.py -v`
Expected: 6 passed

- [ ] **Step 5: Run the full suite (no regressions)**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: all pass (24 existing + 6 new)

- [ ] **Step 6: Commit**

```bash
git add src/generate_report.py tests/test_generate_report.py
git commit -m "feat(report): HTML report core — summary tiles, timeline, escaping"
```

---

### Task 2: "Why it fired" cards with SVG evidence bars

**Files:**

- Modify: `src/generate_report.py` (add card renderers; wire into `build_report`)
- Modify: `tests/test_generate_report.py` (add card tests)

**Interfaces:**

- Consumes: `esc`, `source_key`, `build_report` from Task 1.
- Produces: `render_cards(alerts: List[dict]) -> str`, `render_card(alert: dict, scale: int) -> str`, `render_bar(value: float, scale: float) -> str`, `metric_value(alert: dict) -> int`. `build_report` body becomes summary + cards + timeline.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_generate_report.py`:

```python
def test_cards_show_why_it_fired() -> None:
    page = build_report(SAMPLE_ALERTS, ["run.json"])
    assert "<svg" in page  # evidence bars for scan + dns cards
    assert "distinct destination ports" in page
    assert "DNS requests" in page
    assert "IP&harr;MAC conflict" in page


def test_bar_scales_within_type_group() -> None:
    two_scans = [
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "type": "possible_port_scan",
            "details": {"source_ip": "10.0.0.1", "unique_ports_in_window": 5, "window_seconds": 20},
        },
        {
            "timestamp": "2026-07-18T12:00:05+00:00",
            "type": "possible_port_scan",
            "details": {"source_ip": "10.0.0.2", "unique_ports_in_window": 10, "window_seconds": 20},
        },
    ]
    page = build_report(two_scans, ["run.json"])
    # larger value renders a full-width fill (260), smaller renders half (130)
    assert 'width="260" height="16" fill="#c0392b"' in page
    assert 'width="130" height="16" fill="#c0392b"' in page


def test_non_numeric_metric_does_not_crash() -> None:
    bad = [
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "type": "possible_port_scan",
            "details": {"source_ip": "10.0.0.1", "unique_ports_in_window": "not-a-number"},
        }
    ]
    page = build_report(bad, ["bad.json"])
    assert "10.0.0.1" in page
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_generate_report.py -v`
Expected: the 3 new tests FAIL (no `<svg` / card copy in page); the 6 from Task 1 still pass.

- [ ] **Step 3: Implement the card renderers**

In `src/generate_report.py`, add after `esc`:

```python
BAR_WIDTH = 260
BAR_HEIGHT = 16

METRIC_KEYS = {
    "possible_port_scan": "unique_ports_in_window",
    "dns_burst_anomaly": "requests_in_window",
}


def metric_value(alert: dict) -> int:
    key = METRIC_KEYS.get(alert.get("type", ""))
    if key is None:
        return 0
    try:
        return int(alert.get("details", {}).get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def render_bar(value: float, scale: float) -> str:
    fraction = min(value / scale, 1.0) if scale > 0 else 0.0
    fill = round(BAR_WIDTH * fraction)
    return (
        f'<svg width="{BAR_WIDTH}" height="{BAR_HEIGHT}" role="img">'
        f'<rect width="{BAR_WIDTH}" height="{BAR_HEIGHT}" fill="#e8e8ee"/>'
        f'<rect width="{fill}" height="{BAR_HEIGHT}" fill="#c0392b"/>'
        "</svg>"
    )


def render_card(alert: dict, scale: int) -> str:
    alert_type = alert.get("type", "unknown")
    details = alert.get("details", {})
    timestamp = esc(alert.get("timestamp", "?"))
    if alert_type == "possible_port_scan":
        value = metric_value(alert)
        body = (
            f"<p><strong>{esc(source_key(alert))}</strong> hit <strong>{value}</strong> "
            f"distinct destination ports within {esc(details.get('window_seconds', '?'))}s "
            "&mdash; at or above the scan threshold.</p>" + render_bar(value, scale)
        )
    elif alert_type == "dns_burst_anomaly":
        value = metric_value(alert)
        body = (
            f"<p><strong>{esc(source_key(alert))}</strong> sent <strong>{value}</strong> "
            f"DNS requests within {esc(details.get('window_seconds', '?'))}s "
            "&mdash; at or above the burst threshold.</p>" + render_bar(value, scale)
        )
    elif alert_type == "possible_arp_spoofing":
        body = (
            f"<p><strong>{esc(details.get('ip', '?'))}</strong> was known as "
            f"<code>{esc(details.get('known_mac', '?'))}</code> but was claimed by "
            f"<code>{esc(details.get('observed_mac', '?'))}</code> "
            "&mdash; IP&harr;MAC conflict.</p>"
        )
    else:
        items = "".join(
            f"<li><code>{esc(key)}</code>: {esc(value)}</li>" for key, value in details.items()
        )
        body = f"<ul>{items or '<li>no details recorded</li>'}</ul>"
    return (
        f'<article class="card"><h3>{esc(alert_type)}</h3>'
        f'<p class="ts">{timestamp}</p>{body}</article>'
    )


def render_cards(alerts: List[dict]) -> str:
    if not alerts:
        return ""
    by_type: dict[str, List[dict]] = {}
    for alert in alerts:
        by_type.setdefault(alert.get("type", "unknown"), []).append(alert)
    sections = []
    for alert_type, group in sorted(by_type.items()):
        scale = max((metric_value(alert) for alert in group), default=0)
        cards = "".join(render_card(alert, scale) for alert in group)
        sections.append(
            f'<section><h2>{esc(alert_type)}</h2><div class="cards">{cards}</div></section>'
        )
    return "\n".join(sections)
```

Wire into `build_report` — change the `if alerts:` branch to:

```python
        body = render_summary(alerts) + render_cards(alerts) + render_timeline(alerts)
```

Append to `CSS` (inside the existing string):

```css
.cards{display:flex;gap:1rem;flex-wrap:wrap}
.card{border:1px solid #ddd;border-left:4px solid #c0392b;border-radius:8px;padding:1rem;flex:1;min-width:16rem}
.card .ts{color:#666;font-size:.85rem}
```

Design note (spec decision): the alert doesn't store the threshold — it fired *at* ≥ threshold, so the max value within the type group is the bar scale and card copy says "at or above the … threshold". No threshold plumbing.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_generate_report.py -v`
Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
git add src/generate_report.py tests/test_generate_report.py
git commit -m "feat(report): per-detection 'why it fired' cards with SVG evidence bars"
```

---

### Task 3: CLI — `run()` / `parse_args()` / `__main__`, real-data verification

**Files:**

- Modify: `src/generate_report.py` (append CLI block)
- Modify: `tests/test_generate_report.py` (add `run()` test)

**Interfaces:**

- Consumes: `build_report` (Tasks 1–2); `summarize_logs.load_alerts(path: Path) -> List[dict]` (existing).
- Produces: `run(paths: List[Path], output: Path) -> None` — reads all logs, writes one HTML file, prints a one-line confirmation. CLI: positional `logs` (`nargs="*"`, default demo log), `--output`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_generate_report.py`:

```python
def test_run_merges_logs_and_writes_html(tmp_path: Path) -> None:
    from generate_report import run

    log_a = tmp_path / "a.json"
    log_b = tmp_path / "b.json"
    log_a.write_text(json.dumps(SAMPLE_ALERTS[:1]), encoding="utf-8")
    log_b.write_text(json.dumps(SAMPLE_ALERTS[1:]), encoding="utf-8")
    output = tmp_path / "out" / "report.html"

    run([log_a, log_b], output)

    page = output.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "a.json" in page and "b.json" in page
    assert ">3<" in page  # alerts merged across files
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_generate_report.py::test_run_merges_logs_and_writes_html -v`
Expected: FAIL — `ImportError: cannot import name 'run'`

- [ ] **Step 3: Implement the CLI**

In `src/generate_report.py`: extend the imports at the top —

```python
import argparse
from pathlib import Path

from summarize_logs import load_alerts, source_key
```

Append at the bottom:

```python
DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "logs" / "pcap_alerts.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "logs" / "report.html"


def run(paths: List[Path], output: Path) -> None:
    alerts: List[dict] = []
    for path in paths:
        alerts.extend(load_alerts(path))
    report = build_report(alerts, [path.name for path in paths])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"[*] Report written to {output} ({len(alerts)} alerts)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render alert JSON logs as a self-contained HTML report"
    )
    parser.add_argument(
        "logs",
        nargs="*",
        type=Path,
        default=[DEFAULT_INPUT],
        help="Alert JSON files (default: logs/pcap_alerts.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output HTML path (default: logs/report.html)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(paths=args.logs, output=args.output)
```

(Defaults are anchored to the script's own location, same pattern as `generate_demo_pcap.py`, so it works from any cwd.)

- [ ] **Step 4: Run the full test file**

Run: `.venv/bin/python -m pytest tests/test_generate_report.py -v`
Expected: 10 passed

- [ ] **Step 5: Verify end-to-end on real data**

```bash
cd src && python generate_report.py && cd ..
```

Expected stdout: `[*] Report written to .../logs/report.html (3 alerts)`
Then verify content:

```bash
grep -c "card" logs/report.html   # expect > 0
grep "192.168.8.60" logs/report.html >/dev/null && echo OK
```

Expected: `OK`. Open `logs/report.html` in a browser if available — three cards (scan / DNS / ARP), tiles, timeline.

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/python -m pytest tests/ -v`
Expected: all pass (24 existing + 10 new)

- [ ] **Step 7: Commit**

```bash
git add src/generate_report.py tests/test_generate_report.py
git commit -m "feat(report): CLI entry point with demo-log default; verified on real data"
```

Do NOT commit `logs/report.html` in this task — whether the generated report is checked in as a submission artifact is decided in Task 4.

---

### Task 4: Wiring — README, CLAUDE.md, work plan; decide on committing the artifact

**Files:**

- Modify: `README.md` (add run example to the existing usage section)
- Modify: `CLAUDE.md` (Running block + architecture list)
- Modify: `docs/work_plan.md` (check off Phase 6 items)

**Interfaces:**

- Consumes: the working CLI from Task 3. Produces: docs only.

- [ ] **Step 1: Add run example to README.md**

Find the existing usage/run section in `README.md` (it mirrors CLAUDE.md's Running block) and add, after the `summarize_logs.py` example, matching the surrounding formatting:

```bash
# Render one or more alert logs as a self-contained HTML report:
python generate_report.py ../logs/pcap_alerts.json --output ../logs/report.html
```

- [ ] **Step 2: Update CLAUDE.md**

In the Running block, after the `summarize_logs.py` example, add:

```bash
# Render alert logs as a self-contained HTML report (defaults: demo log -> logs/report.html):
python generate_report.py
```

In the Architecture section, after the `generate_demo_pcap.py` bullet, add:

```markdown
- **[src/generate_report.py](src/generate_report.py)** — standalone HTML report generator, no
  scapy dependency. Reads alert JSON logs (reusing `load_alerts`/`source_key` from
  `summarize_logs.py`) and writes one self-contained `logs/report.html` (inline CSS/SVG, no
  external references): summary tiles, per-detection "why it fired" cards, and a chronological
  timeline. Default input is `logs/pcap_alerts.json`; paths are anchored to the script location.
```

- [ ] **Step 3: Check off Phase 6 in docs/work_plan.md**

Flip the six Phase 6 checkboxes from `- [ ]` to `- [x]`.

- [ ] **Step 4: Verify docs commands actually work**

```bash
cd src && python generate_report.py ../logs/pcap_alerts.json --output ../logs/report.html && cd ..
```

Expected: `[*] Report written to ../logs/report.html (3 alerts)` — exits 0. Confirms the README command line is copy-pasteable.

- [ ] **Step 5: Decide artifact check-in**

`logs/` already contains committed submission artifacts (`pcap_alerts.json`, CSVs, pcap). Generate a fresh `logs/report.html` and include it in the commit **as a submission artifact**, consistent with that convention.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md docs/work_plan.md logs/report.html
git commit -m "docs(report): wire HTML report into README/CLAUDE.md; check off phase 6"
```

---

## Self-Review (done at plan-writing time)

- **Spec coverage:** input/output + defaults (T3), summary tiles (T1), why-it-fired cards incl. ARP conflict + generic fallback (T2), timeline (T1), escaping (T1), empty log (T1), self-contained assertion (T1), never-crash on unknown/missing/non-numeric (T1+T2), README/CLAUDE wiring (T4). Artifact-publish demo step from spec is optional at demo time — intentionally not a build task.
- **Placeholders:** none; every code step has complete code.
- **Type consistency:** `build_report(alerts: List[dict], source_names: List[str]) -> str` used identically in all tasks; `run(paths: List[Path], output: Path)` matches Task 3 test.
