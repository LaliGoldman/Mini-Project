"""Generate a demo PCAP for offline analysis (no live network / sudo needed)."""

from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap  # type: ignore

# Anchored to this file's location so the output lands in the repo-level logs/
# no matter which directory the script is run from.
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "logs" / "demo_capture.pcap"


GATEWAY_MAC = "aa:bb:cc:dd:ee:f0"
DNS_CLIENT_MAC = "aa:bb:cc:dd:ee:50"
SCANNER_MAC = "aa:bb:cc:dd:ee:60"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def build_packets() -> list:
    packets = []
    base = 1_700_000_000.0

    # Normal-looking DNS then burst from same private source.
    # All Ether addresses are pinned: Ether() defaults are resolved from the
    # local machine at write time, which would make the pcap machine-dependent.
    for i in range(20):
        pkt = (
            Ether(src=DNS_CLIENT_MAC, dst=GATEWAY_MAC)
            / IP(src="192.168.8.50", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"host{i}.example.com"))
        )
        pkt.time = base + i * 0.2
        packets.append(pkt)

    # SYN port-scan-like behavior from private IP
    for port in range(1, 25):
        pkt = (
            Ether(src=SCANNER_MAC, dst=GATEWAY_MAC)
            / IP(src="192.168.8.60", dst="192.168.8.1")
            / TCP(sport=40000, dport=port, flags="S")
        )
        pkt.time = base + 10 + port * 0.05
        packets.append(pkt)

    # ARP conflict: same IP, two different MACs
    arp1 = Ether(src="aa:bb:cc:dd:ee:01", dst=BROADCAST_MAC) / ARP(
        op=2, psrc="192.168.8.10", hwsrc="aa:bb:cc:dd:ee:01"
    )
    arp1.time = base + 20
    arp2 = Ether(src="aa:bb:cc:dd:ee:02", dst=BROADCAST_MAC) / ARP(
        op=2, psrc="192.168.8.10", hwsrc="aa:bb:cc:dd:ee:02"
    )
    arp2.time = base + 21
    packets.extend([arp1, arp2])

    return packets


def main(out: Path = DEFAULT_OUTPUT) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(out), packets)
    print(f"[*] Wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main()
