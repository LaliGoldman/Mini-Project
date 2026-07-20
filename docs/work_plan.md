# Mini Project Work Plan

Course 202-1-4481, BGU. Defensive direction (instructor-approved).
Canonical submitted version: [WORK_PLAN_HE.docx](WORK_PLAN_HE.docx) (Hebrew). Final report: [FINAL_REPORT.md](FINAL_REPORT.md).
Team: **trio** — Yuval Notkin, Shmuel Avivi, Ayala Goldman.

## Project Title

Vulnerability Monitoring and Mapping Based on Network Traffic Sniffing (Basic Network Traffic Anomaly Monitor).

## Scope and System Boundaries

Defensive tool that monitors local network traffic and detects suspicious patterns in a controlled lab.

In scope:

- Capture packets from a selected interface.
- Detect three anomaly patterns: port-scan-like behavior, ARP mapping conflicts, DNS bursts.
- Write alerts to terminal + JSON logs.

Out of scope: exploit development, malware deployment, attacking production systems.

## Goal and Objectives

Build a lightweight monitoring tool demonstrating attacker-style traffic patterns and defensive detection.

1. Live packet sniffing.
2. Rule-based anomaly detection.
3. Structured incident logs.
4. Detection in controlled scenarios.
5. Document strengths, weaknesses, future work.

## Scenarios

1. Normal baseline traffic — validate low-noise behavior.
2. Port-scan simulation — trigger scan detection.
3. ARP conflict simulation — trigger ARP alert.
4. DNS burst simulation — trigger DNS anomaly.

## Milestones and Timeline

| Week | Work |
| --- | --- |
| 1 | Requirements, architecture, environment, baseline logging |
| 2 | Scan / ARP / DNS detectors |
| 3 | Controlled tests, threshold tuning, log export + summary |
| 4 | Final documentation, demo steps, submission package |

## Challenges and Risks

- Generating realistic yet safe test traffic.
- False positives on noisy networks.
- Platform permissions for capture.
- Thresholds that generalize across environments.

## Strengths

- Clear fit to course goals; easy to demo with measurable outputs.
- Defensive and safe in a lab setup; extendable to further IDS features.

## Tools

Python 3.10+, scapy, stdlib (argparse, collections, datetime, json, pathlib).

## Remaining tasks

### Phase 1 — Correctness

- [x] DNS: filter `DNS.qr == 0` (queries only) — `src/detection.py:150`
- [x] DNS: add private-source filter
- [x] Live: try/finally around sniff+flush — `src/detector.py:27-33`

### Phase 2 — Reproducibility

- [x] Demo pcap generator + capture — `src/generate_demo_pcap.py`, `logs/demo_capture.pcap`
- [x] Remove stray `logs/alerts.json` (not part of submission log set)

### Phase 3 — Tests

- [x] pytest: 3 alert types fire on crafted packets — `tests/test_detection.py`
- [x] pytest: clean traffic → no alerts — `tests/test_detection.py`
- [x] pytest → `requirements.txt`
- [x] Detection edge cases: cooldown, window trimming, private-source filters, gratuitous ARP skip, flush schema
- [x] `summarize_logs`: counts by type/source, CSV exports, load errors — `tests/test_summarize_logs.py`
- [x] End-to-end: demo pcap → `analyze_pcap` → exact alert set — `tests/test_pcap_pipeline.py`

### Phase 4 — Polish

- [ ] ARP: document trust-on-first-use, or key on `op == 2`
- [ ] Pin scapy version

### Phase 5 — Docs

- [x] Real milestones / scenarios / challenges (from submitted plan)
- [ ] Convert FINAL_REPORT.md → PDF/Word for upload
- [ ] Add signed originality + AI-use declaration forms (from Moodle)

### Phase 6 — Visual report (HTML)

Goal: give the headless monitor a demo-able face. A self-contained HTML report,
generated from our own alert JSON, that visualizes each detection **with the
evidence that triggered it** — not a generic metrics dashboard.

- [x] `src/generate_report.py` — scapy-free, convention-matched CLI
      (`from __future__`, type hints, `argparse`, `run()/parse_args()/__main__`);
      reads one or more alert JSON logs, writes one self-contained
      `logs/report.html` (inline CSS + inline SVG, no external deps / server / sudo)
- [x] Summary tiles: total alerts, counts by type, counts by source IP
- [x] Per-type "why it fired" cards from `details`:
      port scan (`unique_ports_in_window` vs threshold),
      DNS burst (`requests_in_window` vs threshold),
      ARP conflict (`known_mac → observed_mac`)
- [x] Chronological alert timeline
- [x] pytest: report generates from a fixture log; asserts key facts appear in HTML
- [x] Wire into README run section; demo-able offline (open in browser / publish as Artifact)
- [x] Harden against malformed logs: `details` None/non-dict, non-string `type`,
      non-numeric metrics — render partial output, never crash — `tests/test_generate_report.py`
- [x] Verified end-to-end by hand: demo pcap → `analyze_pcap` → `generate_report` →
      committed `logs/report.html` byte-identical to regeneration; 37/37 tests green

Phase 6 complete (2026-07-20); pushed to `origin/yuval`.

---

## Phase 7 — Engine hardening and a fourth detector (added after submission of this plan)

Two review findings drove this phase. Both were limitations we had recorded ourselves:
the report's own observation that home-network DNS bursts produced probable false positives,
and "unusual DNS by domain" sitting unimplemented in the future-work list.

### 7a — Engine hardening

- [x] Bound the monitor's own memory: `prune()` drops scan/DNS/fanout/cooldown state for sources
      that have gone quiet, so a flood of spoofed source addresses cannot exhaust the detector.
      Behaviour-neutral — a test asserts identical alerts at prune intervals of 1 and 10,000
- [x] `arp_table` deliberately exempt from pruning, with the trade-off documented in code:
      an expiring table would let a spoofer wait out one window and claim an address unchallenged
- [x] Mask ECN bits (ECE/CWR) before the pure-SYN test — a SYN with flags `0xC2` previously
      bypassed port-scan detection entirely

### 7b — `possible_dns_tunnel`

- [x] Fourth heuristic: unique subdomains under one parent domain per source, requiring a high
      unique-to-total ratio so re-queried CDN hostnames don't fire
- [x] `--fanout-threshold` on both front-ends (default 15)
- [x] **Rebuilt the demo capture's benign DNS traffic.** The original 20 lookups were
      `host0..host19.example.com` — 20 unique subdomains of one parent, no repeats, i.e. exactly
      the tunnelling pattern. Our reference "legitimate" traffic was shaped like an attack, and
      the new rule would have flagged it. It now spans many parent domains with repeats
- [x] Demo capture gained a genuine tunnel source (`192.168.8.70`), so `.50` trips the volume rule
      only and `.70` trips both — the contrast that shows the new rule *adds* detection
- [x] Report card + timeline evidence for the new type
- [x] Limitations documented, not hidden: last-two-labels grouping instead of a Public Suffix
      List, and a cold cache defeating the ratio check
- [x] Verified: 54/54 tests green; demo pipeline, HTML report and CSV exports regenerated

Phase 7 complete (2026-07-20).
