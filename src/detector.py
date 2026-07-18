from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import sniff  # type: ignore

from detection import DetectionEngine


def run(
    interface: str,
    duration: int,
    output: Path,
    scan_threshold: int,
    dns_threshold: int,
    window: int,
) -> None:
    engine = DetectionEngine(
        output=output,
        scan_threshold=scan_threshold,
        dns_threshold=dns_threshold,
        window=window,
    )

    print(f"[*] Starting capture on interface={interface}, duration={duration}s")
    sniff(
        iface=interface,
        prn=engine.process_packet,
        store=False,
        timeout=duration,
    )
    engine.flush()
    print(f"[*] Capture complete. Alerts written to {output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Basic network anomaly monitor (live capture)")
    parser.add_argument("--interface", required=True, help="Interface name (example: en0)")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration in seconds")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("logs/alerts.json"),
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
    parser.add_argument("--window", type=int, default=10, help="Sliding window in seconds")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(
        interface=args.interface,
        duration=args.duration,
        output=args.output,
        scan_threshold=args.scan_threshold,
        dns_threshold=args.dns_threshold,
        window=args.window,
    )
