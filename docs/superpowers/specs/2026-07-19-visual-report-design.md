# Visual HTML Report — Design Spec

Course mini-project (BGU 202-1-4481), defensive network anomaly monitor.
Phase 6 of [work_plan.md](../../work_plan.md).

## Problem

The monitor is headless: it emits JSON alert logs and nothing a grader *sees*.
Goal is a demo-able face that visualizes real detections **with the evidence that
triggered each one** — not a generic metrics dashboard. Built only from our own
artifacts (alert JSON produced by `detector.py` / `analyze_pcap.py`).

## Non-goals

- No web server, no database, no deployment. (YAGNI; also avoids resembling any
  other project's architecture.)
- No new runtime dependency. Report generation is **scapy-free**, stdlib only,
  matching `summarize_logs.py`.
- No live capture / sudo required to produce or view the report.

## Component

New script `src/generate_report.py` — a standalone reporting tool alongside
`summarize_logs.py`. Convention-matched to the repo:
`from __future__ import annotations`, full type hints, `argparse` CLI with
`run()` + `parse_args()` + `__main__` block.

Reuses from `summarize_logs.py` (import, don't duplicate):
- `load_alerts(path)` — read + validate the JSON array.
- `source_key(alert)` — pull `source_ip` or `ip` from `details`.

## Input / output

- **Input**: one or more alert JSON logs (positional args, like `summarize_logs.py`).
  Default when none given: `logs/pcap_alerts.json` (the deterministic demo output).
- **Output**: one self-contained `logs/report.html` (`--output` to override).
  Inline CSS + inline SVG only. No external CSS/JS/fonts/images — opens offline in
  any browser and is publishable as an Artifact unchanged.

## Alert schema (fixed, already in use)

Top-level `timestamp` / `type` / `details`. Three types:

- `possible_port_scan` — details: `source_ip`, `unique_ports_in_window`, `window_seconds`
- `dns_burst_anomaly` — details: `source_ip`, `requests_in_window`, `window_seconds`
- `possible_arp_spoofing` — details: `ip`, `known_mac`, `observed_mac`

The generator must not crash on an unknown type or missing detail key — render
what is present, fall back to a generic card.

## Page structure

1. **Header** — project title, source file name(s), generated-from counts.
2. **Summary tiles** — total alerts; counts by type; counts by source IP.
3. **Per-detection "why it fired" cards**, grouped by type, each showing the
   evidence from `details`:
   - Port scan: `unique_ports_in_window` vs threshold (window N s) — an SVG bar of
     ports-seen filling toward the threshold line.
   - DNS burst: `requests_in_window` vs threshold (window N s) — same bar treatment.
   - ARP conflict: `ip` with `known_mac → observed_mac` shown as a conflict.
   - Threshold is not stored in the alert; derive the "trigger line" as the alert's
     own count (it fired at exactly ≥ threshold), and label the measured value.
4. **Chronological timeline** — all alerts sorted by `timestamp`, one row each:
   time, type, source, one-line evidence summary.

## Rendering approach

Plain Python string building (f-strings / small helper functions per section).
No templating dependency. HTML-escape every value pulled from the log
(`html.escape`) so a crafted log can't break the page. Bars are inline `<svg>`
with width proportional to value; a marker line for the trigger threshold.

## Error handling

- Missing input file → `load_alerts` raises `FileNotFoundError` (existing behavior).
- Empty alert list → valid report with zeroed tiles and an explicit "no alerts"
  note, not a crash.
- Unknown alert type / missing detail field → generic card from whatever keys
  exist; never raise.

## Testing (TDD)

`tests/test_generate_report.py`, pytest, scapy-free:

- Given a fixture log with all three alert types → generated HTML contains each
  source IP, each measured value (e.g. `unique_ports_in_window`), and the ARP
  `known_mac`/`observed_mac`.
- Empty log → report generates, contains a "no alerts" marker, no exception.
- Output is a single file with no `http`/`https` external references (assert no
  `src="http`, `href="http`, no `<link rel="stylesheet"`) — proves self-contained.
- HTML-escaping: a log with `<script>` in a field appears escaped, not raw.

## Wiring

- Add a run example to `README.md` and to the CLAUDE.md "Running" block.
- Optional demo step: publish `report.html` as an Artifact for the presentation.

## Difficulty / risk

Low. Single stdlib script, fixed input schema, deterministic input already exists
(`logs/pcap_alerts.json`). Main care points: HTML-escaping and graceful handling
of missing keys.
