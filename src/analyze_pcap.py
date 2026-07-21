from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import PcapReader  # type: ignore

from detection import DetectionEngine, packet_timestamp


def run(
    pcap_path: Path,
    output: Path,
    scan_threshold: int,
    dns_threshold: int,
    window: int,
    fanout_threshold: int = 15,
) -> None:
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    engine = DetectionEngine(
        output=output,
        scan_threshold=scan_threshold,
        dns_threshold=dns_threshold,
        fanout_threshold=fanout_threshold,
        window=window,
    )

    print(f"[*] Analyzing PCAP: {pcap_path}")
    # Streamed rather than rdpcap()'d: a real capture can be far larger than
    # available memory, and the engine only ever needs one packet at a time.
    packet_count = 0
    with PcapReader(str(pcap_path)) as packets:
        for packet in packets:
            engine.process_packet(packet, now=packet_timestamp(packet))
            packet_count += 1
    print(f"[*] Processed {packet_count} packets")
    engine.flush()
    print(f"[*] Analysis complete. {len(engine.logger.alerts)} alerts written to {output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline PCAP anomaly analysis")
    parser.add_argument("--pcap", type=Path, required=True, help="Path to .pcap / .pcapng file")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("logs/pcap_alerts.json"),
        help="JSON output path for alerts",
    )
    parser.add_argument(
        "--scan-threshold",
        type=int,
        default=20,
        help="Unique destination ports per source within window",
    )
    parser.add_argument(
        "--dns-threshold",
        type=int,
        default=30,
        help="DNS requests per source within window",
    )
    parser.add_argument(
        "--fanout-threshold",
        type=int,
        default=15,
        help="Unique subdomains under one parent domain per source within window",
    )
    parser.add_argument("--window", type=int, default=10, help="Sliding window in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(
        pcap_path=args.pcap,
        output=args.output,
        scan_threshold=args.scan_threshold,
        dns_threshold=args.dns_threshold,
        fanout_threshold=args.fanout_threshold,
        window=args.window,
    )
