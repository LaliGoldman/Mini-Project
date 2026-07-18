"""Generate a demo PCAP for offline analysis (no live network / sudo needed)."""

from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, wrpcap  # type: ignore


def build_packets() -> list:
    packets = []
    base = 1_700_000_000.0

    # Normal-looking DNS then burst from same private source
    for i in range(20):
        pkt = (
            Ether()
            / IP(src="192.168.8.50", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"host{i}.example.com"))
        )
        pkt.time = base + i * 0.2
        packets.append(pkt)

    # SYN port-scan-like behavior from private IP
    for port in range(1, 25):
        pkt = Ether() / IP(src="192.168.8.60", dst="192.168.8.1") / TCP(sport=40000, dport=port, flags="S")
        pkt.time = base + 10 + port * 0.05
        packets.append(pkt)

    # ARP conflict: same IP, two different MACs
    arp1 = Ether(src="aa:bb:cc:dd:ee:01") / ARP(op=2, psrc="192.168.8.10", hwsrc="aa:bb:cc:dd:ee:01")
    arp1.time = base + 20
    arp2 = Ether(src="aa:bb:cc:dd:ee:02") / ARP(op=2, psrc="192.168.8.10", hwsrc="aa:bb:cc:dd:ee:02")
    arp2.time = base + 21
    packets.extend([arp1, arp2])

    return packets


def main() -> None:
    out = Path("logs/demo_capture.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    packets = build_packets()
    wrpcap(str(out), packets)
    print(f"[*] Wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main()
