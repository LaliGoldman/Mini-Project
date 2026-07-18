from __future__ import annotations

import json
from pathlib import Path

import pytest

import analyze_pcap
import generate_demo_pcap


def test_demo_packets_have_pinned_ether_addresses() -> None:
    # Ether() without explicit src/dst is filled from the local machine at
    # serialization time, making the "deterministic" pcap machine-dependent.
    for packet in generate_demo_pcap.build_packets():
        ether = packet.getlayer(0)
        assert ether.src is not None, packet.summary()
        assert ether.dst is not None, packet.summary()


def test_default_output_is_anchored_to_repo_root_not_cwd() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    assert generate_demo_pcap.DEFAULT_OUTPUT == repo_root / "logs" / "demo_capture.pcap"
    assert generate_demo_pcap.DEFAULT_OUTPUT.is_absolute()


def test_demo_pcap_triggers_all_three_alert_types(tmp_path: Path) -> None:
    pcap = tmp_path / "logs" / "demo_capture.pcap"
    generate_demo_pcap.main(out=pcap)
    assert pcap.exists()

    output = tmp_path / "logs" / "pcap_alerts.json"
    # Documented demo thresholds (see CLAUDE.md / README run instructions).
    analyze_pcap.run(
        pcap_path=pcap,
        output=output,
        scan_threshold=8,
        dns_threshold=10,
        window=20,
    )

    written = json.loads(output.read_text(encoding="utf-8"))
    fired = sorted(
        (a["type"], a["details"].get("source_ip") or a["details"].get("ip"))
        for a in written
    )
    assert fired == [
        ("dns_burst_anomaly", "192.168.8.50"),
        ("possible_arp_spoofing", "192.168.8.10"),
        ("possible_port_scan", "192.168.8.60"),
    ]
