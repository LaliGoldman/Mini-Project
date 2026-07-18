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
| `detection.py` | Shared detection logic used by live and offline modes |

### Alert types
1. **dns_burst_anomaly** – many DNS requests from one source within a short time window  
2. **possible_port_scan** – many unique destination ports (SYN packets from private sources)  
3. **possible_arp_spoofing** – the same IP appears with different MAC addresses  

### Output
- Real-time alerts in the terminal
- JSON log files
- CSV summary export

---

## 3. How to Run the Tool

### Setup
```bash
cd network-anomaly-monitor
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
  --scan-threshold 8 --dns-threshold 10 --window 20
```

---

## 4. Experiments and Results

### Test environment
- OS: macOS
- Interface: `en0`
- Live capture requires `sudo`

### Comparison table

| File | Thresholds | Total alerts | Types |
|------|------------|--------------|--------|
| `run_a.json` | scan=8, dns=10, window=20 | 3 | DNS burst ×3 |
| `run_b.json` | scan=12, dns=15, window=20 | 3 | DNS burst ×3 |
| `run_after_tuning.json` | scan=12, dns=15, window=20 | 4 | DNS burst ×4 |
| `pcap_alerts.json` | scan=8, dns=10, window=20 | 3 | DNS + Port Scan + ARP |

### Conclusions
1. **DNS burst** appeared consistently on a home network – some alerts may be false positives.
2. **Threshold tuning** changes sensitivity: lower thresholds increase detection but also increase noise.
3. **Offline PCAP analysis** allowed a controlled demonstration of all three alert types (DNS, Port Scan, ARP) without depending on live network noise.

### Evidence
The following files are included with the submission:
- `logs/run_a.json`, `logs/run_b.json`, `logs/run_after_tuning.json`
- `logs/pcap_alerts.json`, `logs/demo_capture.pcap`
- `logs/alerts_export.csv`, `logs/summary_by_type.csv`

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
- Working product with measurable outputs (JSON/CSV)
- Modular design: live + offline + summary
- Clear academic discussion of sensitivity vs. false positives
- Safe and legal – defensive tool in an authorized environment

### Weaknesses
- Rule-based detection only (no automatic learning)
- Depends on the network environment and noise level
- No graphical user interface

---

## 7. Social Engineering – Short Perspective

Social engineering usually focuses on deceiving a user (email, extension, malicious link).  
This project shows a complementary angle: even without a clear “bait,” a normal user **does not notice** traffic anomalies such as DNS bursts or ARP mapping changes.

Conclusion: network-level monitoring matters because humans do not inspect the traffic layer in real time.  
This supports the need for a simple monitoring tool, even in home/lab environments.

---

## 8. Creativity and Paradigm Shift

Instead of building a classic attack tool, we built a **measurable defensive system**:
- Threshold comparison as a research method
- Separation between live and offline analysis
- Focused filtering (SYN + private IP) to reduce noise

Paradigm shift: an IDS does not have to be a heavy commercial product – a lightweight rule-based tool can still teach meaningful network-security concepts.

---

## 9. Team Work Division (Trio)

| Area | Content |
|------|---------|
| Live detection and tuning | `detector.py`, `detection.py`, threshold tuning |
| Analysis and logs | `analyze_pcap.py`, `summarize_logs.py`, CSV |
| Documentation and demo | Work plan, final report, test scenarios |

---

## 10. Improvements Made During the Project

- Filtering invalid ARP cases (`0.0.0.0`)
- Port-scan detection limited to SYN packets from private sources
- Added log-summary module
- Added offline PCAP analysis
- Created a controlled demo PCAP to trigger all three alert types

---

## 11. Future Work

- Dynamic baseline by time of day
- Simple GUI for alert visualization
- Additional detection rules (for example unusual DNS by domain)
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
network-anomaly-monitor/
  src/
    detection.py
    detector.py
    analyze_pcap.py
    summarize_logs.py
    generate_demo_pcap.py
  logs/
    run_a.json
    run_b.json
    run_after_tuning.json
    pcap_alerts.json
    demo_capture.pcap
    alerts_export.csv
    summary_by_type.csv
  requirements.txt
  README.md
```

### B. Requirements
- Python 3
- Scapy (`requirements.txt`)
