from __future__ import annotations

import json
from pathlib import Path

import pytest

import analyze_pcap
import generate_demo_pcap


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


def run_demo(tmp_path: Path) -> list:
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
        fanout_threshold=15,
        window=20,
    )
    return json.loads(output.read_text(encoding="utf-8"))


def test_demo_pcap_triggers_every_alert_type(tmp_path: Path) -> None:
    fired = sorted(
        (a["type"], a["details"].get("source_ip") or a["details"].get("ip"))
        for a in run_demo(tmp_path)
    )
    assert fired == [
        ("dns_burst_anomaly", "192.168.8.50"),
        ("dns_burst_anomaly", "192.168.8.70"),
        ("possible_arp_spoofing", "192.168.8.10"),
        ("possible_dns_tunnel", "192.168.8.70"),
        ("possible_port_scan", "192.168.8.60"),
    ]


def test_benign_dns_burst_is_not_flagged_as_a_tunnel(tmp_path: Path) -> None:
    """The specificity guarantee: the tunnel rule must add detection, not echo.

    192.168.8.50 is a page-load-shaped burst -- high volume, many parent
    domains, repeated lookups. It must trip the volume rule and only that one.
    192.168.8.70 carries the same volume but the tunnelling *shape*, and trips
    both. If a change to the demo capture ever makes .50 look like a tunnel,
    the two rules have stopped being independent and this fails.
    """
    by_source: dict[str, set] = {}
    for alert in run_demo(tmp_path):
        source = alert["details"].get("source_ip") or alert["details"].get("ip")
        by_source.setdefault(source, set()).add(alert["type"])

    assert by_source["192.168.8.50"] == {"dns_burst_anomaly"}
    assert by_source["192.168.8.70"] == {"dns_burst_anomaly", "possible_dns_tunnel"}
