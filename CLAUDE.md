# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A course mini-project (BGU "Topics in Network Security", 202-1-4481). The implemented code is a
**defensive** network anomaly monitor: it sniffs traffic (live or from a PCAP) and emits JSON
alerts for four heuristics — TCP SYN port scans, ARP spoofing (IP↔MAC conflicts), DNS request
bursts, and DNS tunneling (unique-subdomain fanout under one parent domain).

The [assignment brief](docs/mini_project_network_security.md) frames the project as **offensive**
(build/propagate "malware"). The team went **defensive** instead, and the **instructor approved
this in writing** — so the mismatch is settled; treat the defensive monitor as the sanctioned scope.

Team is a **trio** (Yuval Notkin, Shmuel Avivi, Ayala Goldman). The submitted deliverables live in
[docs/](docs/): [FINAL_REPORT.md](docs/FINAL_REPORT.md), [work_plan.md](docs/work_plan.md) (English),
and `WORK_PLAN_HE.docx` (Hebrew, the copy submitted to the lecturer).

## Running

Install deps with `pip install -r requirements.txt` (the only runtime dependency is **scapy**;
`pytest` is needed for the tests).
Python 3.12. Scripts import `detection` as a top-level module, so **run them from inside `src/`**
(or add `src/` to `PYTHONPATH`).

```bash
# Generate the deterministic demo capture (no live network / sudo needed).
# Writes to the repo-level logs/demo_capture.pcap regardless of the current dir.
python src/generate_demo_pcap.py

cd src
# Offline analysis of that capture (thresholds tuned to trigger every alert type):
python analyze_pcap.py --pcap ../logs/demo_capture.pcap --output ../logs/pcap_alerts.json \
    --scan-threshold 8 --dns-threshold 10 --fanout-threshold 15 --window 20

# Live capture (needs root/CAP_NET_RAW for the interface):
sudo python detector.py --interface eth0 --duration 120 --output ../logs/alerts.json

# Summarize / compare one or more alert JSON logs, export CSV:
python summarize_logs.py ../logs/run_a.json ../logs/run_b.json \
    --csv ../logs/alerts_export.csv --summary-csv ../logs/summary_by_type.csv

# Render alert logs as a self-contained HTML report (defaults: demo log -> logs/report.html):
python generate_report.py
```

`generate_demo_pcap.py` builds a fixed set of packets so offline analysis reproduces the same
alerts every run — this is the reproducible evidence path, replacing the need for a captured
`.pcap`. It contains four scenarios:

- `192.168.8.50` — a **benign-shaped** DNS burst: high volume, but spread across many parent
  domains with repeats. Trips the volume rule and **must not** trip the tunneling rule.
- `192.168.8.70` — a **DNS tunnel**: 20 unique subdomains of one parent, no repeats. Trips both.
- `192.168.8.60` — a 24-port SYN sweep.
- `192.168.8.10` — an ARP IP↔MAC conflict.

The `.50` / `.70` contrast is the point: it demonstrates the tunneling rule *adds* detection rather
than echoing the volume rule. `tests/test_pcap_pipeline.py` pins it, so editing `BENIGN_LOOKUPS`
into something tunnel-shaped (many unique subdomains of one parent, as the original demo
accidentally had) fails the suite.

Shared detection tuning flags (both `detector.py` and `analyze_pcap.py`):
`--scan-threshold` (default 20 unique dports), `--dns-threshold` (default 30 requests),
`--fanout-threshold` (default 15 unique subdomains per parent), `--window` (default 10s
sliding window). The logs in `logs/` were produced with different
thresholds (e.g. `run_a`/`run_b` use a 20s window) to demonstrate before/after tuning.

Tests are pytest, in `tests/` (run from the repo root — `conftest.py` puts `src/` on the path):

```bash
python -m pytest tests/
```

There is no linter config or build step in the repo.

## Architecture

The detection logic is centralized so the two capture front-ends stay thin and identical in
behavior:

- **[src/detection.py](src/detection.py)** — the whole engine. `DetectionEngine.process_packet()`
  is the single entry point both front-ends feed packets into.
  - `WindowState` holds the per-source sliding-window bookkeeping: deques of `(time, dport)` for
    scans, deques of timestamps for DNS volume, deques of `(time, qname)` keyed by
    `(source, parent_domain)` for DNS fanout, and an `ip → mac` table for ARP. Queues are trimmed
    by `window_seconds` on every event.
  - `can_alert(key, now)` is a per-`(type, source)` **cooldown** (one alert per source per window)
    so a sustained attack produces one alert, not thousands. Any new detection type should route
    through it.
  - `prune(now)` runs every `PRUNE_INTERVAL_PACKETS` packets and deletes scan/DNS/cooldown entries
    for sources that have gone quiet, so spoofed-source floods can't grow the tables without
    bound. It is behaviour-neutral (the queue dicts are defaultdicts). **`arp_table` is exempt on
    purpose** — an expiring ARP table would let a spoofer wait out the window and claim an address
    unchallenged.
  - `AlertLogger` writes the alert file on **every** alert, so a capture killed outright still
    leaves its alerts on disk. `flush()` remains and is idempotent — `detector.py` calls it in a
    `finally` (live capture can be interrupted), `analyze_pcap.py` calls it bare at the end of the
    run (a finite file, nothing to interrupt) — either way an alert-free run produces an empty
    array rather than no file.
  - DNS is evaluated by **two orthogonal rules on the same packet**: `dns_burst_anomaly` (volume)
    and `possible_dns_tunnel` (shape — unique subdomains under one `parent_domain`, requiring a
    unique-to-total ratio ≥ `DNS_TUNNEL_MIN_UNIQUE_RATIO` so re-queried CDN hosts don't fire).
    `parent_domain()` is last-two-labels, **not** a Public Suffix List — documented, not solved.
  - Port-scan detection only counts **private-source** pure-SYN packets: TCP flags are masked with
    `TCP_CONTROL_BITS` (`0x3F`) before comparing to `TCP_SYN`, so ECN bits (ECE/CWR) on an
    otherwise-plain SYN don't hide a scanner, while SYN+PSH/ACK/FIN still don't count.
    ARP handler skips gratuitous/broadcast (`0.0.0.0`, `ff:ff:ff:ff:ff:ff`).

- **[src/detector.py](src/detector.py)** — live front-end. Wraps scapy `sniff()`, passing
  `engine.process_packet` as the callback. Uses wall-clock (`utc_now`) for event time.

- **[src/analyze_pcap.py](src/analyze_pcap.py)** — offline front-end. Replays a `.pcap`/`.pcapng`
  through the same engine — **streamed via `PcapReader`**, never `rdpcap()`, so a capture larger
  than memory still works — but passes each packet's **own capture time** via
  `process_packet(packet, now=packet_timestamp(packet))`. This is the key difference from live
  mode: the sliding windows advance on the recorded timeline, not real time, so offline results
  are deterministic and independent of how fast the file is processed.

- **[src/summarize_logs.py](src/summarize_logs.py)** — standalone reporting tool, no scapy
  dependency. Reads the alert JSON (a flat array of `{timestamp, type, details}`), counts by type
  and by source IP (`source_ip` or `ip` from `details`), prints per-file summaries plus a
  cross-file comparison when given multiple logs, and exports detailed + summary CSVs.

- **[src/generate_demo_pcap.py](src/generate_demo_pcap.py)** — writes `logs/demo_capture.pcap`, a
  fixed synthetic capture with hard-coded packet `.time` values that triggers every alert type.
  It is the reproducible input behind `logs/pcap_alerts.json`. The output path is anchored to the
  script's own location (`DEFAULT_OUTPUT`), so it lands in the repo-level `logs/` from any cwd.

- **[src/generate_report.py](src/generate_report.py)** — standalone HTML report generator, no
  scapy dependency. Reads alert JSON logs (reusing `load_alerts`/`source_key` from
  `summarize_logs.py`) and writes one self-contained `logs/report.html` (inline CSS/SVG, no
  external references): summary tiles, per-detection "why it fired" cards, and a chronological
  timeline. Default input is `logs/pcap_alerts.json`; paths are anchored to the script location.

Naming caveat: `detector.py` (the live runner) vs `detection.py` (the engine module) are easy to
confuse — the engine class is `DetectionEngine` and lives in `detection.py`.

## Conventions

- Style: `from __future__ import annotations`, full type hints, `argparse`-based CLIs with a
  `run()` + `parse_args()` + `__main__` block per script. Match this when adding a new tool.
- Alert schema is fixed: top-level `timestamp`/`type`/`details`, with the source identifier inside
  `details` as either `source_ip` or `ip`. `summarize_logs.py` depends on this shape.
