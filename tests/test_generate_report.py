from __future__ import annotations

import json
from pathlib import Path

from generate_report import build_report

SAMPLE_ALERTS = [
    {
        "timestamp": "2026-07-18T12:00:00+00:00",
        "type": "possible_port_scan",
        "details": {
            "source_ip": "192.168.8.60",
            "unique_ports_in_window": 8,
            "window_seconds": 20,
        },
    },
    {
        "timestamp": "2026-07-18T12:00:01+00:00",
        "type": "dns_burst_anomaly",
        "details": {
            "source_ip": "192.168.8.50",
            "requests_in_window": 10,
            "window_seconds": 20,
        },
    },
    {
        "timestamp": "2026-07-18T12:00:02+00:00",
        "type": "possible_arp_spoofing",
        "details": {
            "ip": "192.168.8.10",
            "known_mac": "aa:bb:cc:dd:ee:01",
            "observed_mac": "aa:bb:cc:dd:ee:02",
        },
    },
]


def test_report_contains_sources_and_evidence() -> None:
    page = build_report(SAMPLE_ALERTS, ["pcap_alerts.json"])
    assert "pcap_alerts.json" in page
    assert "192.168.8.60" in page
    assert "192.168.8.50" in page
    assert "192.168.8.10" in page
    # evidence values surface in the timeline
    assert "8 unique ports" in page
    assert "10 DNS requests" in page
    assert "aa:bb:cc:dd:ee:01" in page
    assert "aa:bb:cc:dd:ee:02" in page


def test_report_counts_by_type_and_source() -> None:
    page = build_report(SAMPLE_ALERTS, ["run.json"])
    assert "possible_port_scan" in page
    assert "dns_burst_anomaly" in page
    assert "possible_arp_spoofing" in page
    assert ">3<" in page  # total-alerts tile


def test_empty_log_renders_note_not_crash() -> None:
    page = build_report([], ["empty.json"])
    assert "No alerts" in page
    assert ">0<" in page


def test_output_is_self_contained() -> None:
    page = build_report(SAMPLE_ALERTS, ["run.json"])
    assert 'src="http' not in page
    assert 'href="http' not in page
    assert "<link" not in page
    assert "<script" not in page


def test_log_values_are_html_escaped() -> None:
    hostile = [
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "type": "<script>alert(1)</script>",
            "details": {"source_ip": "<img src=x>"},
        }
    ]
    page = build_report(hostile, ["hostile.json"])
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "<img src=x>" not in page


def test_unknown_type_and_missing_keys_render_generic() -> None:
    weird = [
        {"timestamp": "2026-07-18T12:00:00+00:00", "type": "novel_thing", "details": {"foo": 1}},
        {"type": "possible_port_scan", "details": {}},
        {},
    ]
    page = build_report(weird, ["weird.json"])
    assert "novel_thing" in page
    assert "foo" in page


def test_cards_show_why_it_fired() -> None:
    page = build_report(SAMPLE_ALERTS, ["run.json"])
    assert "<svg" in page  # evidence bars for scan + dns cards
    assert "distinct destination ports" in page
    assert "DNS requests" in page
    assert "IP&harr;MAC conflict" in page


def test_bar_scales_within_type_group() -> None:
    two_scans = [
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "type": "possible_port_scan",
            "details": {"source_ip": "10.0.0.1", "unique_ports_in_window": 5, "window_seconds": 20},
        },
        {
            "timestamp": "2026-07-18T12:00:05+00:00",
            "type": "possible_port_scan",
            "details": {"source_ip": "10.0.0.2", "unique_ports_in_window": 10, "window_seconds": 20},
        },
    ]
    page = build_report(two_scans, ["run.json"])
    # larger value renders a full-width fill (260), smaller renders half (130)
    assert 'width="260" height="16" fill="#c0392b"' in page
    assert 'width="130" height="16" fill="#c0392b"' in page


def test_non_numeric_metric_does_not_crash() -> None:
    bad = [
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "type": "possible_port_scan",
            "details": {"source_ip": "10.0.0.1", "unique_ports_in_window": "not-a-number"},
        }
    ]
    page = build_report(bad, ["bad.json"])
    assert "10.0.0.1" in page
    assert "hit <strong>0</strong>" in page


def test_none_details_does_not_crash() -> None:
    bad = [
        {"timestamp": "2026-07-18T12:00:00+00:00", "type": "possible_port_scan", "details": None},
        {"timestamp": "2026-07-18T12:00:01+00:00", "type": "possible_arp_spoofing", "details": None},
    ]
    page = build_report(bad, ["bad.json"])
    assert "possible_port_scan" in page
    assert "possible_arp_spoofing" in page
