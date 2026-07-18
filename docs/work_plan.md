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
