# Network Traffic Anomaly Monitor

Defensive tool that monitors network traffic and detects suspicious patterns:
- DNS burst
- Port-scan-like behavior
- ARP mapping conflicts

## Setup
```bash
cd network-anomaly-monitor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Live monitoring
```bash
sudo python src/detector.py --interface en0 --duration 90 --scan-threshold 12 --dns-threshold 15 --window 20
```

## Summarize logs
```bash
python src/summarize_logs.py logs/run_a.json logs/run_b.json logs/run_after_tuning.json logs/pcap_alerts.json \
  --csv logs/alerts_export.csv
```

## Offline PCAP analysis
```bash
# Create a demo PCAP (no sudo required):
python src/generate_demo_pcap.py

# Analyze it:
python src/analyze_pcap.py --pcap logs/demo_capture.pcap --output logs/pcap_alerts.json \
  --scan-threshold 8 --dns-threshold 10 --window 20
```

## Project structure
- `src/detection.py` – shared detection logic
- `src/detector.py` – live monitoring
- `src/analyze_pcap.py` – PCAP analysis
- `src/summarize_logs.py` – log summary and CSV export
- `src/generate_demo_pcap.py` – demo PCAP generator
- `FINAL_REPORT.md` – final report (English)

## Notes
- Use only in authorized environments.
- Live capture usually requires `sudo`.
