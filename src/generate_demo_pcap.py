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
TUNNEL_MAC = "aa:bb:cc:dd:ee:70"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# A page load: high query volume, but spread across many different parent
# domains with repeats as several resources come from the same host. This trips
# the volume rule and must NOT trip the tunnelling rule -- that contrast is the
# point of having both, so keep the per-parent unique count low if edited.
BENIGN_LOOKUPS = [
    "www.example.com",
    "api.example.org",
    "cdn1.example.net",
    "www.example.com",
    "img.example.info",
    "static.example.biz",
    "cdn1.example.net",
    "api.example.org",
    "fonts.example.net",
    "www.example.com",
    "analytics.example.org",
    "img.example.info",
    "cdn1.example.net",
    "www.example.com",
    "static.example.biz",
    "api.example.org",
    "img.example.info",
    "www.example.com",
    "fonts.example.net",
    "cdn1.example.net",
]

# Exfiltration over DNS: payload encoded into the leftmost label, so every
# lookup is a unique hostname under one attacker-controlled parent and nothing
# is ever re-queried.
TUNNEL_PARENT = "t.exfil-demo.test"
TUNNEL_QUERY_COUNT = 20


def build_packets() -> list:
    packets = []
    base = 1_700_000_000.0

    # Benign-shaped DNS burst from one private source.
    # All Ether addresses are pinned: Ether() defaults are resolved from the
    # local machine at write time, which would make the pcap machine-dependent.
    for i, qname in enumerate(BENIGN_LOOKUPS):
        pkt = (
            Ether(src=DNS_CLIENT_MAC, dst=GATEWAY_MAC)
            / IP(src="192.168.8.50", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname))
        )
        pkt.time = base + i * 0.2
        packets.append(pkt)

    # DNS tunnelling from a second private source.
    for i in range(TUNNEL_QUERY_COUNT):
        pkt = (
            Ether(src=TUNNEL_MAC, dst=GATEWAY_MAC)
            / IP(src="192.168.8.70", dst="8.8.8.8")
            / UDP(sport=54000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"p{i:04x}payload{i}.{TUNNEL_PARENT}"))
        )
        pkt.time = base + 30 + i * 0.2
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
