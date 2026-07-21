# Final Hardening and Report Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last three gaps before submission — alerts surviving an abrupt kill, streaming
PCAP reads, and the report sections that are underclaimed or factually loose.

**Architecture:** Two small, contained code changes (`AlertLogger` persists on every alert instead
of only on `flush()`; `analyze_pcap` streams with `PcapReader` instead of loading the whole capture
via `rdpcap`) plus targeted edits to `docs/FINAL_REPORT.md`. No new modules, no new dependencies, no
change to the alert JSON schema — `summarize_logs.py` and `generate_report.py` stay untouched.

**Tech Stack:** Python 3.12, scapy, pytest. Run tests from the repo root; `tests/conftest.py` puts
`src/` on the path.

## Global Constraints

- Keep the alert file a **flat JSON array** of `{timestamp, type, details}`. The schema is fixed and
  `summarize_logs.py` depends on it. Do not switch to JSONL.
- Do not add dependencies. `requirements.txt` stays `scapy` + `pytest`.
- Match existing style: `from __future__ import annotations`, full type hints, `argparse` CLIs with
  `run()` + `parse_args()` + `__main__`.
- `engine.flush()` must remain safe to call and must remain in the callers' `finally` blocks.
- The demo pipeline output must not change. `logs/pcap_alerts.json` has 5 alerts:
  `dns_burst_anomaly` ×2 (`192.168.8.50`, `192.168.8.70`), `possible_dns_tunnel` (`192.168.8.70`),
  `possible_port_scan` (`192.168.8.60`), `possible_arp_spoofing` (`192.168.8.10`).
- Full suite is currently **54 tests, all passing**. It must stay green at every commit.
- **Factual claims in the report must be true.** Confirmed with the team: the live runs
  (`run_a`/`run_b`/`run_after_tuning`) were genuinely captured on a teammate's macOS machine on
  `en0`; offline analysis and the test suite run on Linux. Section 7 is written as **analysis only**
  — no experiment involving real people took place, and the plan must not imply one did.

---

### Task 1: Alerts survive an abrupt kill

`AlertLogger` accumulates alerts in memory and only writes on `flush()`. The `finally` blocks in
both front-ends cover exceptions and Ctrl-C, but not `SIGKILL`, a dropped SSH session, or a laptop
losing power — so an unattended live run can lose an entire session's alerts.

Fix: write the file every time an alert is appended. Rewriting the whole array on each alert is
O(n²) in principle, but the per-`(type, source)` cooldown caps alert volume to a handful per window,
so this is the right trade for a course project — it keeps the schema, keeps the file valid JSON at
all times, and needs no changes to any consumer.

**Files:**
- Modify: `src/detection.py` (the `AlertLogger` class)
- Test: `tests/test_detection.py`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `AlertLogger.log()` now persists to `output_path` as a side effect. `AlertLogger.flush()`
  keeps its exact signature (`() -> None`) and stays idempotent, so both front-ends' `finally`
  blocks are unchanged.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_detection.py`, immediately after `test_flush_writes_alert_schema`:

```python
def test_alerts_are_persisted_without_an_explicit_flush(tmp_path: Path) -> None:
    # A live capture killed outright (SIGKILL, lost session, power loss) never
    # reaches the finally block, so alerts must already be on disk by then.
    engine = make_engine(tmp_path)
    feed_dns_burst(engine, "192.168.1.50", qr=0, count=5)

    written = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert [a["type"] for a in written] == ["dns_burst_anomaly"]
    assert written[0]["details"]["source_ip"] == "192.168.1.50"


def test_flush_is_idempotent_after_incremental_writes(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    feed_dns_burst(engine, "192.168.1.50", qr=0, count=5)
    engine.flush()
    engine.flush()

    written = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert len(written) == 1


def test_empty_run_still_writes_a_valid_empty_array(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    engine.flush()

    assert json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8")) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_detection.py -k "persisted or idempotent or empty_run" -v`

Expected: `test_alerts_are_persisted_without_an_explicit_flush` FAILS with
`FileNotFoundError: [Errno 2] No such file or directory: '.../alerts.json'`.
The other two PASS already — they are regression guards for this change, not new behaviour.

- [ ] **Step 3: Write the implementation**

In `src/detection.py`, replace the `AlertLogger.log` and `AlertLogger.flush` methods with:

```python
    def log(self, alert_type: str, details: dict, timestamp: Optional[datetime] = None) -> None:
        ts = (timestamp or utc_now()).isoformat()
        payload = {
            "timestamp": ts,
            "type": alert_type,
            "details": details,
        }
        self.alerts.append(payload)
        # Persist immediately. A live capture that is killed outright never
        # reaches its finally block, and buffering the whole session in memory
        # would lose every alert. Alert volume is bounded by the per-source
        # cooldown, so rewriting the array each time is cheap enough.
        self._write()
        if self.print_alerts:
            print(f"[ALERT] {ts} {alert_type} | {details}")

    def _write(self) -> None:
        self.output_path.write_text(json.dumps(self.alerts, indent=2), encoding="utf-8")

    def flush(self) -> None:
        """Write the alert file. Callers still invoke this so an alert-free run
        produces an empty array rather than no file at all."""
        self._write()
```

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest tests/ -q`

Expected: `57 passed` (54 existing + 3 new).

- [ ] **Step 5: Verify the demo pipeline output is unchanged**

```bash
cp logs/pcap_alerts.json /tmp/before_alerts.json
cd src
python analyze_pcap.py --pcap ../logs/demo_capture.pcap --output ../logs/pcap_alerts.json \
    --scan-threshold 8 --dns-threshold 10 --fanout-threshold 15 --window 20
cd ..
diff /tmp/before_alerts.json logs/pcap_alerts.json && echo "UNCHANGED"
```

Expected: `UNCHANGED`, and `git status --short` shows no modification to `logs/`.

- [ ] **Step 6: Commit**

```bash
git add src/detection.py tests/test_detection.py
git commit -m "fix(detection): persist alerts as they fire, not only on flush

A live capture killed outright -- SIGKILL, a dropped session, power loss --
never reaches the finally block that calls flush(), so a whole session's
alerts were lost. AlertLogger now writes the file on every alert.

Rewriting the array per alert is O(n^2) in principle, but the per-(type,
source) cooldown bounds alert volume, and this keeps the fixed JSON-array
schema that summarize_logs.py and generate_report.py depend on. flush() is
retained and idempotent so an alert-free run still produces an empty array."
```

---

### Task 2: Stream the capture instead of loading it whole

`analyze_pcap.run()` calls `rdpcap()`, which reads the entire capture into memory. That is fine for
the 66-packet demo and fails on a real multi-gigabyte capture — which contradicts the README's claim
that "any real `.pcap` / `.pcapng` works the same way". `PcapReader` yields packets one at a time.

The user-visible consequence: the current code prints `Loaded N packets` *before* processing, which a
streaming reader cannot know. The count moves to the end, where it is genuinely known.

**Files:**
- Modify: `src/analyze_pcap.py`
- Test: `tests/test_pcap_pipeline.py`

**Interfaces:**
- Consumes: `analyze_pcap.run(pcap_path, output, scan_threshold, dns_threshold, window, fanout_threshold)`
  — signature unchanged, so `tests/test_pcap_pipeline.py::run_demo` needs no edit.
- Produces: nothing new for later tasks.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_pcap_pipeline.py`, after the existing imports and before `run_demo`:

```python
def test_capture_is_streamed_not_loaded_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # rdpcap() materialises the entire capture in memory, which fails on a
    # real multi-gigabyte file. Reading must go through PcapReader instead.
    def explode(*args, **kwargs):
        raise AssertionError("rdpcap() loads the whole capture into memory")

    monkeypatch.setattr(analyze_pcap, "rdpcap", explode, raising=False)

    pcap = tmp_path / "demo_capture.pcap"
    generate_demo_pcap.main(out=pcap)
    output = tmp_path / "alerts.json"

    analyze_pcap.run(
        pcap_path=pcap,
        output=output,
        scan_threshold=8,
        dns_threshold=10,
        fanout_threshold=15,
        window=20,
    )

    assert len(json.loads(output.read_text(encoding="utf-8"))) == 5
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest tests/test_pcap_pipeline.py::test_capture_is_streamed_not_loaded_whole -v`

Expected: FAIL with `AssertionError: rdpcap() loads the whole capture into memory`.

- [ ] **Step 3: Write the implementation**

In `src/analyze_pcap.py`, change the import line:

```python
from scapy.all import PcapReader  # type: ignore
```

and replace the body of `run()` between the `print("[*] Analyzing PCAP: ...")` line and the
`engine.flush()` line with:

```python
    print(f"[*] Analyzing PCAP: {pcap_path}")
    # Streamed rather than rdpcap()'d: a real capture can be far larger than
    # available memory, and the engine only ever needs one packet at a time.
    packet_count = 0
    with PcapReader(str(pcap_path)) as packets:
        for packet in packets:
            engine.process_packet(packet, now=packet_timestamp(packet))
            packet_count += 1
    print(f"[*] Processed {packet_count} packets")
```

- [ ] **Step 4: Run the full suite**

Run: `python -m pytest tests/ -q`

Expected: `58 passed`.

- [ ] **Step 5: Verify the demo pipeline output is unchanged**

```bash
cp logs/pcap_alerts.json /tmp/before_alerts.json
cd src
python analyze_pcap.py --pcap ../logs/demo_capture.pcap --output ../logs/pcap_alerts.json \
    --scan-threshold 8 --dns-threshold 10 --fanout-threshold 15 --window 20
cd ..
diff /tmp/before_alerts.json logs/pcap_alerts.json && echo "UNCHANGED"
```

Expected: the run prints `[*] Processed 66 packets` and the diff reports `UNCHANGED`.

- [ ] **Step 6: Update the two docs that describe the reading strategy**

In `CLAUDE.md`, in the `src/analyze_pcap.py` bullet under "Architecture", replace
`Replays a `.pcap`/`.pcapng` through the same engine` with:

```markdown
  through the same engine — **streamed via `PcapReader`**, never `rdpcap()`, so a capture larger
  than memory still works — but passes each packet's **own capture time** via
```

(keeping the rest of that bullet as-is).

In `docs/FINAL_REPORT.md`, add to the section 10 improvements list:

```markdown
- Switched offline analysis to a streaming capture reader, so a real capture larger than available
  memory can be analysed rather than only small demo files
```

- [ ] **Step 7: Commit**

```bash
git add src/analyze_pcap.py tests/test_pcap_pipeline.py CLAUDE.md docs/FINAL_REPORT.md
git commit -m "perf(analyze-pcap): stream the capture instead of loading it whole

rdpcap() materialises every packet in memory, so the README's claim that any
real .pcap works held only for small files. PcapReader yields one packet at a
time, which is all the engine ever needs.

The packet count moves from before processing to after it -- a streaming
reader cannot know the total up front."
```

---

### Task 3: Rewrite section 7 (social engineering)

Worth up to 15 points in the brief and currently four sentences. It stays **analysis only** — no
exercise involving real people took place and the text must not imply one did. The substance comes
from connecting the four detectors to the network-visible stages of social-engineering attack
chains, which is a genuine argument the project's own artifacts support.

**Files:**
- Modify: `docs/FINAL_REPORT.md` (section 7)

**Interfaces:** none — documentation only.

- [ ] **Step 1: Replace section 7 in full**

Replace everything between the `## 7. Social Engineering – Short Perspective` heading and the `---`
that precedes `## 8. Creativity and Paradigm Shift` with:

```markdown
## 7. Social Engineering – Short Perspective

Social engineering is the first stage of an attack, not the whole of it. A phishing mail, a
malicious browser extension, or a rogue "free Wi-Fi" access point only succeeds in getting code
running or traffic redirected. Everything after that point has to cross the network — and that is
where this tool looks.

We did not run an experiment on people; this section is an analysis of where our four detectors sit
in a social-engineering attack chain.

### Where each detector sits in the chain

| Social-engineering entry point | What happens next on the network | Detector that would see it |
|---|---|---|
| Phishing attachment or malicious extension installs a backdoor | Beacons to a command-and-control server, often over DNS because port 53 is rarely blocked | `possible_dns_tunnel` — payload encoded into subdomain labels |
| Same, at the data-theft stage | Files leave the network in DNS queries rather than an obvious upload | `possible_dns_tunnel` + `dns_burst_anomaly` together |
| Victim joins a rogue access point or an attacker gains LAN access | ARP cache poisoning to place the attacker between victim and gateway | `possible_arp_spoofing` — an IP↔MAC mapping that changes |
| Attacker gets a foothold on one machine and looks for others | Sweeps the local network for open services | `possible_port_scan` |

### The asymmetry that matters

Deception works because the target has no way to verify what they are told. The network layer has
the opposite property: an ARP mapping either changed or it did not, and a host either queried 20
unique subdomains of one domain or it did not. Those facts do not depend on the user's judgement,
their mood, or how convincing the pretext was.

This is why network monitoring complements user training rather than duplicating it. Training tries
to reduce how often deception succeeds; monitoring assumes it sometimes will and catches the
consequences. Our demo capture makes that concrete: a user who has been successfully phished has no
way to notice that their machine is making DNS queries with payload in the hostnames, because
nothing in their normal experience of using a computer surfaces that. The monitor notices in under
twenty seconds.

### The honest limit

Detection is not prevention. Every alert this tool raises describes something that has *already*
happened — the backdoor is already installed, the traffic is already redirected. What monitoring buys
is time: the gap between compromise and discovery, which is the window an attacker relies on. It
does nothing about the deception itself.
```

- [ ] **Step 2: Verify the surrounding structure is intact**

Run: `grep -n "^## " docs/FINAL_REPORT.md`

Expected: sections 1–12 each appear exactly once, in order, with `## 7. Social Engineering – Short
Perspective` between sections 6 and 8.

- [ ] **Step 3: Commit**

```bash
git add docs/FINAL_REPORT.md
git commit -m "docs(report): expand the social-engineering analysis

Section 7 was four sentences against a criterion worth up to 15 points. It now
maps each of the four detectors onto the network-visible stage of a social-
engineering attack chain, argues why network-layer facts are verifiable in a
way a pretext is not, and states the limit plainly: detection is not
prevention.

Analysis only -- no exercise involving real people took place, and the text
does not imply one did."
```

---

### Task 4: Correct the report's factual details

Three small inaccuracies, each cheap to fix and disproportionately damaging if a grader finds them
first.

**Files:**
- Modify: `docs/FINAL_REPORT.md` (sections 3, 4, 9)

**Interfaces:** none — documentation only.

- [ ] **Step 1: Fix the setup path in section 3**

The repository directory is `Mini-Project`, not `network-anomaly-monitor`. Replace the setup block:

```bash
cd Mini-Project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- [ ] **Step 2: Attribute the test environment in section 4**

The live captures were genuinely taken on a teammate's macOS machine; offline analysis and the test
suite run on Linux. Say both, so the environment claim is complete rather than merely unexplained.
Replace the "Test environment" block:

```markdown
### Test environment
- **Live captures** (`run_a`, `run_b`, `run_after_tuning`): macOS, interface `en0`, run with `sudo`
  on a team member's machine — live sniffing needs root / `CAP_NET_RAW`
- **Offline analysis, demo capture generation, and the test suite**: Linux, no root required
- The offline path is the reproducible one: it advances the detection windows using each packet's
  recorded capture time, so its results do not depend on the host or on how fast the file is read
```

- [ ] **Step 3: Name the team members in section 9**

The brief states the grade is individual and reflects each student's own contribution, so the
division needs names against it. Replace the section 9 table:

```markdown
| Area | Owner | Content |
|------|-------|---------|
| Live detection and tuning | | `detector.py`, `detection.py`, threshold tuning |
| Analysis and logs | | `analyze_pcap.py`, `summarize_logs.py`, CSV export |
| Documentation and demo | | Work plan, final report, demo capture, test scenarios |
```

**This step needs the team's own input** — fill the Owner column with the three names
(Yuval Notkin, Shmuel Avivi, Ayala Goldman) according to who actually did each area. Do not guess:
an invented division in a document whose grade is explicitly individual is worse than none.

- [ ] **Step 4: Verify no stale references remain**

Run:

```bash
grep -n "network-anomaly-monitor\|three alert types\|all three" docs/FINAL_REPORT.md README.md CLAUDE.md
```

Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add docs/FINAL_REPORT.md
git commit -m "docs(report): correct setup path, environment claim, team attribution

- Setup block referenced a directory name the repository does not use
- The macOS/en0 environment applied only to the live captures; offline
  analysis and the test suite run on Linux. Both are now stated, along with
  why the offline path is the reproducible one
- Section 9 gains an Owner column, since the brief grades each student on
  their own contribution"
```

---

## Final verification

- [ ] **Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: `58 passed`.

- [ ] **Regenerate every artifact with the documented commands and confirm nothing drifted**

```bash
python src/generate_demo_pcap.py
cd src
python analyze_pcap.py --pcap ../logs/demo_capture.pcap --output ../logs/pcap_alerts.json \
    --scan-threshold 8 --dns-threshold 10 --fanout-threshold 15 --window 20
python generate_report.py ../logs/pcap_alerts.json --output ../logs/report.html
cd ..
python src/summarize_logs.py logs/run_a.json logs/run_b.json logs/run_after_tuning.json \
    logs/pcap_alerts.json --csv logs/alerts_export.csv --summary-csv logs/summary_by_type.csv
git status --short
```

Expected: `git status --short` reports **no changes under `logs/`**. Any diff there means a code
change altered detection output and must be explained before submission.

- [ ] **Confirm the Owner column in section 9 is filled in.** This is the one item in the plan that
  cannot be completed without the team, and it must not be left blank at submission.
