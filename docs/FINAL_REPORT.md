# Final Report – Mini Project on Network Security

**Course:** Topics in Network Security (Mini Project on Network Security)  
**Course number:** 202-1-4481  

**Authors:**
- Yuval Notkin – 206374480
- Shmuel Avivi – 318290327
- Ayala Goldman – 315261644

**Project title:** Network Traffic Anomaly Monitor Based on Packet Sniffing

---

## 1. Project Goal

The goal of this project is to build a basic defensive tool that monitors network traffic in real time (and offline), and detects suspicious patterns using rule-based sliding-window logic.

The project demonstrates:
- How normal traffic differs from anomalous traffic
- How a rule-based detection system behaves in practice
- The limits of detection (false positives, threshold sensitivity, encrypted traffic)

---

## 2. System Description

The system is implemented in Python using Scapy. It includes the following main components:

| Component | Role |
|-----------|------|
| `detector.py` | Live sniffing on a selected network interface |
| `analyze_pcap.py` | Offline analysis of a saved PCAP file |
| `summarize_logs.py` | Log summary, run comparison, and CSV export |
| `generate_report.py` | Self-contained HTML report (summary tiles, evidence cards, timeline) |
| `generate_demo_pcap.py` | Deterministic demo capture that triggers every alert type |
| `detection.py` | Shared detection logic used by live and offline modes |
| `tests/` | Automated pytest suite covering the engine and the offline pipeline |

### Alert types
1. **dns_burst_anomaly** – many DNS requests from one source within a short time window  
2. **possible_port_scan** – many unique destination ports (SYN packets from private sources)  
3. **possible_arp_spoofing** – the same IP appears with different MAC addresses  
4. **possible_dns_tunnel** – many *unique subdomains of one parent domain* from one source, with
   almost no repeated lookups  

Rules 1 and 4 are deliberately **orthogonal signals evaluated on the same packets**. The burst rule
asks *how many?*; the tunnelling rule asks *what shape?* DNS tunnelling tools (iodine, dnscat2)
encode payload bytes into the leftmost label, so every lookup is a fresh hostname beneath one
attacker-controlled parent and nothing is ever re-queried. A legitimate burst is the mirror image:
many lookups spread across many *different* parents, with repeats as caches expire. Requiring a
high unique-to-total ratio is what keeps a busy content-delivery domain from being mistaken for a
tunnel.

This rule was **added after the submitted work plan**. It answers a limitation we recorded
ourselves during testing (section 4, conclusion 1: DNS bursts on a home network produced probable
false positives) and implements what we had listed only as future work ("unusual DNS by domain").

### Output
- Real-time alerts in the terminal
- JSON log files
- CSV summary export
- Self-contained HTML report (no external resources; opens in any browser)

---

## 3. How to Run the Tool

### Setup
```bash
cd Mini-Project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Live monitoring
```bash
sudo python src/detector.py --interface en0 --duration 90 --scan-threshold 12 --dns-threshold 15 --window 20
```

### Summarize logs
```bash
python src/summarize_logs.py logs/run_a.json logs/run_b.json logs/run_after_tuning.json logs/pcap_alerts.json \
  --csv logs/alerts_export.csv \
  --summary-csv logs/summary_by_type.csv
```

### Offline PCAP analysis
```bash
python src/generate_demo_pcap.py
python src/analyze_pcap.py --pcap logs/demo_capture.pcap --output logs/pcap_alerts.json \
  --scan-threshold 8 --dns-threshold 10 --fanout-threshold 15 --window 20
```

### HTML report

```bash
python src/generate_report.py logs/pcap_alerts.json --output logs/report.html
```

### Automated tests

```bash
python -m pytest tests/
```

---

## 4. Experiments and Results

### Test environment
- **Live captures** (`run_a`, `run_b`, `run_after_tuning`): macOS, interface `en0`, run with `sudo`
  on a team member's machine — live sniffing needs root / `CAP_NET_RAW`
- **Offline analysis, demo capture generation, and the test suite**: Linux, no root required
- The offline path is the reproducible one: it advances the detection windows using each packet's
  recorded capture time, so its results do not depend on the host or on how fast the file is read

### Comparison table

| File | Thresholds | Total alerts | Types |
|------|------------|--------------|--------|
| `run_a.json` | scan=8, dns=10, window=20 | 3 | DNS burst ×3 |
| `run_b.json` | scan=12, dns=15, window=20 | 3 | DNS burst ×3 |
| `run_after_tuning.json` | scan=12, dns=15, window=20 | 4 | DNS burst ×4 |
| `pcap_alerts.json` | scan=8, dns=10, fanout=15, window=20 | 5 | DNS burst ×2 + DNS tunnel + Port Scan + ARP |

### Conclusions
1. **DNS burst** appeared consistently on a home network – some alerts may be false positives.
2. **Threshold tuning** changes sensitivity: lower thresholds increase detection but also increase noise.
3. **Offline PCAP analysis** allowed a controlled demonstration of every alert type without depending on live network noise.
4. **Two rules on the same traffic beat one.** The demo capture contains two DNS sources of equal
   volume: a page-load-shaped burst (`192.168.8.50`) and an exfiltration tunnel (`192.168.8.70`).
   The volume rule cannot tell them apart — it flags both. The tunnelling rule flags only the
   second. This is the clearest result in the project: it shows that *what* traffic looks like
   carries information that *how much* traffic there is cannot express, and it is the difference
   between counting packets and reasoning about attack structure.

### Automated verification

Beyond the manual runs above, the repository includes a pytest suite (58 tests) that
verifies each detector in isolation — positive cases, negative cases (SYN-ACK packets,
DNS responses, public-source traffic, gratuitous ARP, queries spread across distinct parent
domains, re-queried CDN hostnames), sliding-window trimming, the per-source alert cooldown,
and state pruning — plus end-to-end tests that regenerate the demo PCAP and assert both the
exact set of alerts produced and the specificity contrast described in conclusion 4: that the
benign DNS burst is flagged by the volume rule *only*.

### Evidence
The following files are included with the submission:
- `logs/run_a.json`, `logs/run_b.json`, `logs/run_after_tuning.json`
- `logs/pcap_alerts.json`, `logs/demo_capture.pcap`
- `logs/alerts_export.csv`, `logs/summary_by_type.csv`
- `logs/report.html` (self-contained HTML report rendered from `pcap_alerts.json`)

---

## 5. Challenges and Difficulties

- **Permissions:** Live sniffing requires `sudo`.
- **Home-network noise:** Legitimate traffic can look anomalous.
- **Threshold tuning:** There is no universal threshold – it must fit the environment.
- **HTTPS:** Payload content is encrypted; detection uses traffic patterns (DNS/TCP/ARP), not application content.
- **Team coordination:** Splitting modules across three students while keeping one integrated system.

---

## 6. Strengths and Weaknesses

### Strengths
- Working product with measurable outputs (JSON/CSV/HTML)
- Modular design: live + offline + summary + report, all sharing one detection engine
- Automated pytest suite (58 tests), including an end-to-end reproducible demo pipeline
- Clear academic discussion of sensitivity vs. false positives
- Safe and legal – defensive tool in an authorized environment

### Weaknesses
- Rule-based detection only (no automatic learning)
- Depends on the network environment and noise level
- No interactive GUI (reporting is a static HTML page)
- The ARP IP→MAC table never expires, so a *legitimate* MAC change for an IP (a DHCP lease
  handed to a new device, a NIC replacement) is reported as a conflict. This is a deliberate
  trade-off: an expiring table would let a spoofer stay quiet for one window and then claim the
  address unchallenged, which we judged the worse failure for a security tool.
- An attacker who paces below a threshold (for example a slow port scan spread across many
  windows) evades the sliding-window rules by design.
- The tunnelling rule groups queries by the **last two labels** of the name rather than using a
  Public Suffix List, so names under a multi-part suffix (`a.example.co.uk`) collapse into a
  single bucket and unrelated sites can share it. Solving this properly requires bundling the PSL
  as a data file, which we judged out of scope for a project with one runtime dependency.
- The unique-to-total ratio only speaks once there is evidence of re-querying. A **cold cache** —
  a first-contact burst of distinct hostnames under one shared content-delivery domain — has no
  repeats yet and can still read as a tunnel. The fanout threshold carries that case, since one
  parent domain rarely serves that many distinct hosts for a single page.

---

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
nothing in their normal experience of using a computer surfaces that. In our demo capture the monitor flags it about three seconds after the first tunnelled query — though a slower attacker, pacing below the threshold, would evade the window entirely.

### The honest limit

Detection is not prevention. Every alert this tool raises describes something that has *already*
happened — the backdoor is already installed, the traffic is already redirected. What monitoring buys
is time: the gap between compromise and discovery, which is the window an attacker relies on. It
does nothing about the deception itself.

---

## 8. Creativity and Paradigm Shift

Instead of building a classic attack tool, we built a **measurable defensive system**:
- Threshold comparison as a research method
- Separation between live and offline analysis
- Focused filtering (SYN + private IP) to reduce noise
- Two orthogonal rules over the same DNS packets — volume and structure — so the system can
  distinguish a busy host from a tunnelling one instead of merely flagging both as "a lot of DNS"

Paradigm shift: an IDS does not have to be a heavy commercial product – a lightweight rule-based tool can still teach meaningful network-security concepts.

---

## 9. Team Work Division (Trio)

| Area | Owner | Content |
|------|-------|---------|
| Live detection and tuning | | `detector.py`, `detection.py`, threshold tuning |
| Analysis and logs | | `analyze_pcap.py`, `summarize_logs.py`, CSV export |
| Documentation and demo | | Work plan, final report, demo capture, test scenarios |

---

## 10. Improvements Made During the Project

- Filtering invalid ARP cases (`0.0.0.0`)
- Port-scan detection limited to SYN packets from private sources
- Added log-summary module
- Added offline PCAP analysis
- Created a controlled demo PCAP to trigger every alert type
- Added an automated pytest suite (unit tests per detector + end-to-end pipeline test)
- Added a self-contained HTML report generator (summary tiles, evidence cards, timeline)
- Bounded the monitor's own memory: per-source state for sources that have gone quiet is pruned
  periodically, so an attacker cannot exhaust the detector by flooding it with spoofed source
  addresses (the ARP table is exempt on purpose — see Weaknesses)
- Masked ECN bits out of the TCP flag test, so a SYN carrying ECE/CWR is still counted as a scan
  probe rather than slipping past the filter
- Added a fourth heuristic, `possible_dns_tunnel`, detecting unique-subdomain fanout under one
  parent domain — an orthogonal signal to the existing DNS volume rule
- Switched offline analysis to a streaming capture reader, so a real capture larger than available
  memory can be analysed rather than only small demo files
- Rebuilt the demo capture's benign DNS traffic. The original 20 lookups were
  `host0..host19.example.com` — 20 unique subdomains of one parent with no repeats, which is
  precisely the tunnelling pattern. Our "legitimate" reference traffic was therefore shaped like an
  attack. It now spans many parent domains with repeats, as a real page load does, and a test
  asserts it trips the volume rule *only*

---

## 11. Future Work

- Dynamic baseline by time of day
- Simple GUI for alert visualization
- Public Suffix List support, so `parent_domain` grouping is exact rather than last-two-labels
- Query-name length as a third DNS signal (tunnels pack labels toward the 63-byte limit)
- SIEM integration

---

## 12. Summary

The project met its goal: a defensive anomaly-detection tool for network traffic was built, executed, and tested in both live and offline modes.  
The artifacts (logs, CSV, PCAP) support a clear demonstration of the system’s capabilities and limitations.

This work provided practical understanding of network monitoring, false positives, and detection tuning – and completes the submitted work plan.

---

## Appendices

### A. Project structure
```
Mini-Project/
  src/
    detection.py
    detector.py
    analyze_pcap.py
    summarize_logs.py
    generate_report.py
    generate_demo_pcap.py
  tests/
    conftest.py
    test_detection.py
    test_detector.py
    test_pcap_pipeline.py
    test_summarize_logs.py
    test_generate_report.py
  logs/
    run_a.json
    run_b.json
    run_after_tuning.json
    pcap_alerts.json
    demo_capture.pcap
    alerts_export.csv
    summary_by_type.csv
    report.html
  docs/
    work_plan.md
    FINAL_REPORT.md
  requirements.txt
  README.md
```

### B. Requirements
- Python 3
- Scapy (`requirements.txt`)
