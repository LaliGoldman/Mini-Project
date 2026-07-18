from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from summarize_logs import export_csv, export_summary_csv, load_alerts, summarize_file

SAMPLE_ALERTS = [
    {
        "timestamp": "2026-07-18T12:00:00+00:00",
        "type": "possible_port_scan",
        "details": {"source_ip": "192.168.1.60", "unique_ports_in_window": 20},
    },
    {
        "timestamp": "2026-07-18T12:00:01+00:00",
        "type": "possible_arp_spoofing",
        "details": {"ip": "192.168.1.10", "known_mac": "aa", "observed_mac": "bb"},
    },
    {
        "timestamp": "2026-07-18T12:00:02+00:00",
        "type": "dns_burst_anomaly",
        "details": {"source_ip": "192.168.1.60", "requests_in_window": 30},
    },
    {
        "timestamp": "2026-07-18T12:00:03+00:00",
        "type": "dns_burst_anomaly",
        "details": {},
    },
]


def write_log(path: Path, alerts: list) -> Path:
    path.write_text(json.dumps(alerts), encoding="utf-8")
    return path


def test_summarize_file_counts_by_type_and_source(tmp_path: Path) -> None:
    log = write_log(tmp_path / "run.json", SAMPLE_ALERTS)
    summary = summarize_file(log)
    assert summary["total_alerts"] == 4
    assert summary["by_type"] == {
        "possible_port_scan": 1,
        "possible_arp_spoofing": 1,
        "dns_burst_anomaly": 2,
    }
    # source_ip preferred, ip as fallback, unknown when neither exists
    assert summary["by_source"] == {"192.168.1.60": 2, "192.168.1.10": 1, "unknown": 1}


def test_load_alerts_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_alerts(tmp_path / "nope.json")


def test_load_alerts_rejects_non_array(tmp_path: Path) -> None:
    log = tmp_path / "bad.json"
    log.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_alerts(log)


def test_export_csv_writes_one_row_per_alert(tmp_path: Path) -> None:
    log = write_log(tmp_path / "run.json", SAMPLE_ALERTS)
    summary = summarize_file(log)
    csv_path = tmp_path / "out" / "alerts.csv"
    export_csv([summary], csv_path)
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == ["source_file", "timestamp", "type", "source_ip", "details_json"]
    assert len(rows) == 1 + len(SAMPLE_ALERTS)
    assert rows[1][2] == "possible_port_scan"
    assert rows[1][3] == "192.168.1.60"
    assert json.loads(rows[1][4]) == SAMPLE_ALERTS[0]["details"]


def test_export_summary_csv_counts_per_type(tmp_path: Path) -> None:
    log = write_log(tmp_path / "run.json", SAMPLE_ALERTS)
    summary = summarize_file(log)
    csv_path = tmp_path / "summary.csv"
    export_summary_csv([summary], csv_path)
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == ["source_file", "alert_type", "count"]
    counts = {row[1]: int(row[2]) for row in rows[1:]}
    assert counts == {
        "possible_port_scan": 1,
        "possible_arp_spoofing": 1,
        "dns_burst_anomaly": 2,
    }
