from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import json

import pytest

from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP  # type: ignore

import detection
from detection import DetectionEngine

BASE_TIME = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)


def make_engine(
    tmp_path: Path,
    dns_threshold: int = 5,
    scan_threshold: int = 20,
    window: int = 10,
    fanout_threshold: int = 15,
) -> DetectionEngine:
    return DetectionEngine(
        output=tmp_path / "alerts.json",
        scan_threshold=scan_threshold,
        dns_threshold=dns_threshold,
        fanout_threshold=fanout_threshold,
        window=window,
        print_alerts=False,
    )


def dns_packet(src_ip: str, qr: int, qname: str = "example.com"):
    return (
        IP(src=src_ip, dst="192.168.1.1")
        / UDP(sport=40000, dport=53)
        / DNS(qr=qr, qd=DNSQR(qname=qname))
    )


def feed_dns_burst(engine: DetectionEngine, src_ip: str, qr: int, count: int) -> None:
    for i in range(count):
        packet = dns_packet(src_ip, qr=qr)
        engine.process_packet(packet, now=BASE_TIME + timedelta(milliseconds=100 * i))


def test_dns_query_burst_from_private_source_alerts(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    feed_dns_burst(engine, "192.168.1.50", qr=0, count=5)
    assert [a["type"] for a in engine.logger.alerts] == ["dns_burst_anomaly"]
    assert engine.logger.alerts[0]["details"]["source_ip"] == "192.168.1.50"


def test_dns_responses_do_not_count_toward_burst(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    feed_dns_burst(engine, "192.168.1.1", qr=1, count=10)
    assert engine.logger.alerts == []


def test_dns_burst_from_public_source_ignored(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    feed_dns_burst(engine, "8.8.8.8", qr=0, count=10)
    assert engine.logger.alerts == []


def feed_dns_names(
    engine: DetectionEngine,
    src_ip: str,
    names: list[str],
    step_seconds: float = 0.1,
) -> None:
    for i, name in enumerate(names):
        engine.process_packet(
            dns_packet(src_ip, qr=0, qname=name),
            now=BASE_TIME + timedelta(seconds=step_seconds * i),
        )


def tunnel_names(count: int, parent: str = "t.exfil.test") -> list[str]:
    """Payload-carrying subdomains: every lookup a fresh unique label."""
    return [f"p{i:04x}data{i}.{parent}" for i in range(count)]


# dns_threshold is parked out of reach in these tests so the volume rule stays
# silent and only the fanout rule under test can fire.
QUIET_BURST = 10_000


def test_dns_tunnel_fanout_alerts(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15)
    feed_dns_names(engine, "192.168.1.50", tunnel_names(15))
    assert [a["type"] for a in engine.logger.alerts] == ["possible_dns_tunnel"]
    details = engine.logger.alerts[0]["details"]
    assert details["source_ip"] == "192.168.1.50"
    assert details["parent_domain"] == "exfil.test"
    assert details["unique_subdomains_in_window"] == 15


def test_distinct_parent_domains_do_not_trigger_tunnel(tmp_path: Path) -> None:
    # A page load fans out across many *different* registrable domains. High
    # volume, but no single parent accumulates unique children.
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15)
    feed_dns_names(engine, "192.168.1.50", [f"www.site{i}.example" for i in range(30)])
    assert engine.logger.alerts == []


def test_repeated_qname_does_not_inflate_unique_count(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15)
    feed_dns_names(engine, "192.168.1.50", ["www.example.com"] * 40)
    assert engine.logger.alerts == []


def test_cdn_style_repeats_do_not_trigger_tunnel(tmp_path: Path) -> None:
    # Many unique hostnames under one shared CDN parent, but re-queried as
    # caches expire and pages pull several resources per host. A tunnel never
    # repeats itself; this does, so the unique-to-total ratio holds it back.
    #
    # Note the repeats are interleaved, not appended. A *cold* cache -- 15
    # first-contact lookups with no repeat yet -- has a ratio of 1.0 and does
    # alert; the ratio can only speak once there is re-query evidence. The
    # fanout threshold is what carries that case, since a single parent rarely
    # serves that many distinct hosts on one page. Documented as a limitation.
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15)
    names: list[str] = []
    for i in range(16):
        names.append(f"edge{i}.cloudfront.net")
        names.extend([f"edge{max(0, i - 1)}.cloudfront.net"] * 2)
    feed_dns_names(engine, "192.168.1.50", names)
    assert engine.logger.alerts == []


def test_tunnel_fanout_window_slides(tmp_path: Path) -> None:
    engine = make_engine(
        tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15, window=10
    )
    feed_dns_names(engine, "192.168.1.50", tunnel_names(15), step_seconds=1.0)
    assert engine.logger.alerts == []


def test_tunnel_cooldown_limits_alerts_to_one_per_window(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15)
    feed_dns_names(engine, "192.168.1.50", tunnel_names(60), step_seconds=0.05)
    assert [a["type"] for a in engine.logger.alerts] == ["possible_dns_tunnel"]


def test_short_qnames_are_ignored_for_fanout(tmp_path: Path) -> None:
    # A bare two-label name has no subdomain to carry payload, and grouping it
    # by "last two labels" would make it its own parent.
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, fanout_threshold=15)
    feed_dns_names(engine, "192.168.1.50", [f"site{i}.test" for i in range(30)])
    assert engine.logger.alerts == []


def test_tunnel_state_is_pruned_like_other_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(detection, "PRUNE_INTERVAL_PACKETS", 50)
    engine = make_engine(tmp_path, dns_threshold=QUIET_BURST, window=10)
    feed_dns_names(engine, "192.168.1.50", tunnel_names(10))
    assert len(engine.state.dns_fanout) == 1
    flood_unique_sources(engine, count=30, at=BASE_TIME + timedelta(seconds=300))
    assert engine.state.dns_fanout == {}


def syn_packet(src_ip: str, dport: int, flags: str = "S"):
    return IP(src=src_ip, dst="192.168.1.1") / TCP(sport=40000, dport=dport, flags=flags)


def feed_syn_sweep(
    engine: DetectionEngine,
    src_ip: str,
    ports: range,
    flags: str = "S",
    step_seconds: float = 0.05,
) -> None:
    for i, port in enumerate(ports):
        packet = syn_packet(src_ip, port, flags=flags)
        engine.process_packet(packet, now=BASE_TIME + timedelta(seconds=step_seconds * i))


def test_syn_sweep_from_private_source_alerts(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, scan_threshold=20)
    feed_syn_sweep(engine, "192.168.1.60", ports=range(1, 21))
    assert [a["type"] for a in engine.logger.alerts] == ["possible_port_scan"]
    details = engine.logger.alerts[0]["details"]
    assert details["source_ip"] == "192.168.1.60"
    assert details["unique_ports_in_window"] == 20


def test_syn_ack_packets_do_not_count(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, scan_threshold=20)
    feed_syn_sweep(engine, "192.168.1.60", ports=range(1, 31), flags="SA")
    assert engine.logger.alerts == []


def test_syn_sweep_from_public_source_ignored(tmp_path: Path) -> None:
    # Note: TEST-NET ranges (e.g. 203.0.113.0/24) count as private for
    # ipaddress.is_private, so use a genuinely global address here.
    engine = make_engine(tmp_path, scan_threshold=20)
    feed_syn_sweep(engine, "8.8.8.8", ports=range(1, 31))
    assert engine.logger.alerts == []


def test_repeated_port_does_not_count_as_unique(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, scan_threshold=20)
    for i in range(30):
        packet = syn_packet("192.168.1.60", dport=80)
        engine.process_packet(packet, now=BASE_TIME + timedelta(seconds=0.05 * i))
    assert engine.logger.alerts == []


def test_ports_outside_window_are_trimmed(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, scan_threshold=20, window=10)
    feed_syn_sweep(engine, "192.168.1.60", ports=range(1, 21), step_seconds=1.0)
    assert engine.logger.alerts == []


def arp_packet(psrc: str, hwsrc: str):
    return ARP(op=2, psrc=psrc, hwsrc=hwsrc)


def test_arp_ip_mac_conflict_alerts(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    engine.process_packet(arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:01"), now=BASE_TIME)
    engine.process_packet(
        arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:02"), now=BASE_TIME + timedelta(seconds=1)
    )
    assert [a["type"] for a in engine.logger.alerts] == ["possible_arp_spoofing"]
    details = engine.logger.alerts[0]["details"]
    assert details["ip"] == "192.168.1.10"
    assert details["known_mac"] == "aa:bb:cc:dd:ee:01"
    assert details["observed_mac"] == "aa:bb:cc:dd:ee:02"


def test_arp_consistent_mapping_no_alert(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    for i in range(5):
        engine.process_packet(
            arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:01"),
            now=BASE_TIME + timedelta(seconds=i),
        )
    assert engine.logger.alerts == []


def test_gratuitous_and_broadcast_arp_ignored(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    engine.process_packet(arp_packet("0.0.0.0", "aa:bb:cc:dd:ee:01"), now=BASE_TIME)
    engine.process_packet(
        arp_packet("0.0.0.0", "aa:bb:cc:dd:ee:02"), now=BASE_TIME + timedelta(seconds=1)
    )
    engine.process_packet(
        arp_packet("192.168.1.10", "ff:ff:ff:ff:ff:ff"), now=BASE_TIME + timedelta(seconds=2)
    )
    assert engine.logger.alerts == []


def test_cooldown_limits_alerts_to_one_per_window(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, dns_threshold=5, window=10)
    # Sustained burst inside one window: threshold crossed repeatedly, one alert.
    feed_dns_burst(engine, "192.168.1.50", qr=0, count=50)
    assert [a["type"] for a in engine.logger.alerts] == ["dns_burst_anomaly"]


def test_cooldown_expires_after_window(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, dns_threshold=5, window=10)
    feed_dns_burst(engine, "192.168.1.50", qr=0, count=5)
    for i in range(5):
        packet = dns_packet("192.168.1.50", qr=0)
        engine.process_packet(
            packet, now=BASE_TIME + timedelta(seconds=11, milliseconds=100 * i)
        )
    assert [a["type"] for a in engine.logger.alerts] == [
        "dns_burst_anomaly",
        "dns_burst_anomaly",
    ]


def test_clean_traffic_produces_no_alerts(tmp_path: Path) -> None:
    engine = make_engine(tmp_path, dns_threshold=5, scan_threshold=20)
    for i in range(3):
        engine.process_packet(
            dns_packet("192.168.1.50", qr=0), now=BASE_TIME + timedelta(seconds=i)
        )
    for i, port in enumerate((80, 443, 8080)):
        engine.process_packet(
            syn_packet("192.168.1.50", port), now=BASE_TIME + timedelta(seconds=i)
        )
    for i, port in enumerate(range(1, 30)):
        engine.process_packet(
            syn_packet("192.168.1.50", port, flags="A"), now=BASE_TIME + timedelta(seconds=0.05 * i)
        )
    engine.process_packet(arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:01"), now=BASE_TIME)
    assert engine.logger.alerts == []


def test_syn_with_ecn_bits_still_counts_as_scan(tmp_path: Path) -> None:
    # A SYN may carry ECN negotiation bits (ECE/CWR). Those are still SYN
    # packets and a scanner using them must not slip past the detector.
    engine = make_engine(tmp_path, scan_threshold=20)
    feed_syn_sweep(engine, "192.168.1.60", ports=range(1, 21), flags="SEC")
    assert [a["type"] for a in engine.logger.alerts] == ["possible_port_scan"]


def test_syn_with_payload_flags_does_not_count(tmp_path: Path) -> None:
    # PSH/ACK/FIN alongside SYN is not a scan probe; only the six base TCP
    # control bits are considered, so these must stay filtered out.
    engine = make_engine(tmp_path, scan_threshold=20)
    feed_syn_sweep(engine, "192.168.1.60", ports=range(1, 31), flags="SP")
    assert engine.logger.alerts == []


def flood_unique_sources(engine: DetectionEngine, count: int, at: datetime) -> None:
    """One SYN and one DNS query each from `count` distinct spoofed sources."""
    for i in range(count):
        src = f"10.{i // 256}.{i % 256}.7"
        engine.process_packet(syn_packet(src, dport=80), now=at)
        engine.process_packet(dns_packet(src, qr=0), now=at)


def test_stale_per_source_state_is_pruned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A flood of spoofed source IPs must not grow the monitor's memory without
    # bound -- otherwise the detector itself is a resource-exhaustion target.
    monkeypatch.setattr(detection, "PRUNE_INTERVAL_PACKETS", 50)
    engine = make_engine(tmp_path, window=10)

    flood_unique_sources(engine, count=200, at=BASE_TIME)
    assert len(engine.state.scan_ports) == 200
    assert len(engine.state.dns_requests) == 200

    # Well past the window: every one of those sources is now stale.
    flood_unique_sources(engine, count=25, at=BASE_TIME + timedelta(seconds=60))

    assert len(engine.state.scan_ports) == 25
    assert len(engine.state.dns_requests) == 25


def test_pruning_keeps_sources_still_inside_the_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(detection, "PRUNE_INTERVAL_PACKETS", 10)
    engine = make_engine(tmp_path, window=10)

    engine.process_packet(syn_packet("192.168.1.99", dport=80), now=BASE_TIME)
    # Enough traffic to trigger a sweep, but only 2s later -- still in window.
    flood_unique_sources(engine, count=20, at=BASE_TIME + timedelta(seconds=2))

    assert "192.168.1.99" in engine.state.scan_ports


def test_pruning_never_forgets_arp_mappings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The ARP table is deliberately permanent: expiring it would let a spoofer
    # simply wait out the window and never be flagged.
    monkeypatch.setattr(detection, "PRUNE_INTERVAL_PACKETS", 10)
    engine = make_engine(tmp_path, window=10)

    engine.process_packet(arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:01"), now=BASE_TIME)
    flood_unique_sources(engine, count=50, at=BASE_TIME + timedelta(seconds=600))
    engine.process_packet(
        arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:02"), now=BASE_TIME + timedelta(seconds=900)
    )

    assert [a["type"] for a in engine.logger.alerts] == ["possible_arp_spoofing"]


def test_pruning_does_not_change_detection_results(tmp_path: Path) -> None:
    # Pruning must be behaviour-neutral: an entry trimmed to empty and an
    # entry that was deleted are indistinguishable to the detectors.
    def run_with(interval: int) -> list:
        engine = make_engine(tmp_path, dns_threshold=5, scan_threshold=20, window=10)
        engine.prune_interval = interval
        feed_dns_burst(engine, "192.168.1.50", qr=0, count=8)
        feed_syn_sweep(engine, "192.168.1.60", ports=range(1, 25))
        engine.process_packet(arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:01"), now=BASE_TIME)
        engine.process_packet(
            arp_packet("192.168.1.10", "aa:bb:cc:dd:ee:02"), now=BASE_TIME + timedelta(seconds=1)
        )
        return engine.logger.alerts

    assert run_with(interval=1) == run_with(interval=10_000)


def test_expired_cooldown_entries_are_pruned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(detection, "PRUNE_INTERVAL_PACKETS", 50)
    engine = make_engine(tmp_path, dns_threshold=5, window=10)

    for i in range(40):
        feed_dns_burst(engine, f"10.9.{i}.4", qr=0, count=5)
    assert len(engine.alert_cooldown) == 40

    flood_unique_sources(engine, count=30, at=BASE_TIME + timedelta(seconds=300))
    assert engine.alert_cooldown == {}


def test_flush_writes_alert_schema(tmp_path: Path) -> None:
    engine = make_engine(tmp_path)
    feed_dns_burst(engine, "192.168.1.50", qr=0, count=5)
    engine.flush()
    written = json.loads((tmp_path / "alerts.json").read_text(encoding="utf-8"))
    assert isinstance(written, list) and len(written) == 1
    alert = written[0]
    assert set(alert) == {"timestamp", "type", "details"}
    # Alert fires on the 5th packet of the burst (threshold reached), so the
    # timestamp is that packet's event time, not the window start.
    assert alert["timestamp"] == (BASE_TIME + timedelta(milliseconds=400)).isoformat()
    assert alert["details"]["source_ip"] == "192.168.1.50"


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
