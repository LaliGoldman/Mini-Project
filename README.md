# Network Anomaly Monitor

A defensive network-security tool for the BGU course *Topics in Network Security* (202-1-4481).
It sniffs traffic — live from an interface or offline from a capture file — and emits JSON alerts
for three common attack patterns:

- **TCP SYN port scan** — a single source touching many distinct destination ports with pure-SYN
  packets inside a short window.
- **ARP spoofing** — an IP whose advertised MAC address changes (an IP↔MAC conflict), the signature
  of ARP cache poisoning.
- **DNS request burst** — a source issuing an abnormal number of DNS requests in a short window
  (e.g. tunneling or exfiltration).

The detection logic lives in one engine ([src/detection.py](src/detection.py)); two thin
front-ends feed packets into it — one for live capture, one for replaying a saved capture — so
both behave identically.

## Requirements

- Python 3.12
- [scapy](https://scapy.net/) — the only dependency

```bash
pip install -r requirements.txt
```

The scripts import `detection` as a top-level module, so **run them from inside `src/`** (or add
`src/` to `PYTHONPATH`).

## Usage

### Offline analysis of a capture file (no root needed)

```bash
cd src
python analyze_pcap.py --pcap ../captures/sample.pcapng --output ../logs/pcap_alerts.json
```

Offline mode advances the detection windows using each packet's **recorded** capture time, so
results are deterministic and independent of how fast the file is read.

### Live capture (needs root / CAP_NET_RAW)

```bash
cd src
sudo python detector.py --interface eth0 --duration 120 --output ../logs/alerts.json
```

### Summarize / compare alert logs

`summarize_logs.py` has no scapy dependency. It counts alerts by type and by source IP, compares
multiple runs, and can export CSVs.

```bash
cd src
python summarize_logs.py ../logs/run_a.json ../logs/run_b.json \
    --csv ../logs/alerts_export.csv --summary-csv ../logs/summary_by_type.csv
```

### Render alert logs as an HTML report

`generate_report.py` generates a self-contained HTML report from alert JSON logs, with summary
tiles, per-detection context cards, and a chronological timeline.

```bash
cd src
python generate_report.py ../logs/pcap_alerts.json --output ../logs/report.html
```

## Detection tuning

Both `detector.py` and `analyze_pcap.py` accept the same tuning flags:

- `--scan-threshold` — unique destination ports per source within the window (default **20**).
- `--dns-threshold` — DNS requests per source within the window (default **30**).
- `--window` — sliding-window length in seconds (default **10**).

The pre-generated logs in [logs/](logs/) were produced with different thresholds (e.g. a 20 s
window in `run_a`/`run_b`) to demonstrate before/after tuning.

## Alert format

Alerts are written as a flat JSON array. Each entry has a fixed shape:

```json
{
  "timestamp": "2026-05-05T16:17:40.367182+00:00",
  "type": "dns_burst_anomaly",
  "details": {
    "source_ip": "192.168.8.33",
    "requests_in_window": 17,
    "window_seconds": 20
  }
}
```

`type` is one of `possible_port_scan`, `possible_arp_spoofing`, or `dns_burst_anomaly`. The source
identifier lives inside `details` as `source_ip` (scan/DNS) or `ip` (ARP). To avoid flooding, the
engine emits at most one alert per `(type, source)` per window.

## Project layout

- [src/detection.py](src/detection.py) — the detection engine (shared by both front-ends).
- [src/detector.py](src/detector.py) — live-capture front-end.
- [src/analyze_pcap.py](src/analyze_pcap.py) — offline PCAP front-end.
- [src/summarize_logs.py](src/summarize_logs.py) — reporting / CSV export tool.
- [logs/](logs/) — example alert logs and CSV exports.
- [docs/](docs/) — assignment brief and work plan.
