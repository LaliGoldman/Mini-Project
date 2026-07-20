from __future__ import annotations

import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple

from scapy.all import ARP, DNS, IP, TCP  # type: ignore


# How many packets between sweeps of the per-source bookkeeping. Sweeping on
# every packet would be wasteful; the dicts only need to stay bounded, not be
# exact at every instant.
PRUNE_INTERVAL_PACKETS = 1000

# Mask covering the six base TCP control bits (FIN/SYN/RST/PSH/ACK/URG). The
# top two bits (ECE/CWR) are ECN negotiation and may accompany a legitimate
# SYN, so they are masked off before testing for a pure SYN probe.
TCP_CONTROL_BITS = 0x3F
TCP_SYN = 0x02


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def packet_timestamp(packet) -> datetime:  # noqa: ANN001
    return datetime.fromtimestamp(float(packet.time), tz=timezone.utc)


def is_private_ip(ip_addr: str) -> bool:
    try:
        return ipaddress.ip_address(ip_addr).is_private
    except ValueError:
        return False


class WindowState:
    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self.scan_ports: Dict[str, Deque[Tuple[datetime, int]]] = defaultdict(deque)
        self.dns_requests: Dict[str, Deque[datetime]] = defaultdict(deque)
        self.arp_table: Dict[str, str] = {}

    def _trim_time_queue(self, q: Deque[datetime], now: datetime) -> None:
        while q and (now - q[0]).total_seconds() > self.window_seconds:
            q.popleft()

    def _trim_port_queue(self, q: Deque[Tuple[datetime, int]], now: datetime) -> None:
        while q and (now - q[0][0]).total_seconds() > self.window_seconds:
            q.popleft()

    def add_scan_event(self, src_ip: str, dport: int, now: datetime) -> Set[int]:
        queue = self.scan_ports[src_ip]
        queue.append((now, dport))
        self._trim_port_queue(queue, now)
        return {port for _, port in queue}

    def add_dns_event(self, src_ip: str, now: datetime) -> int:
        queue = self.dns_requests[src_ip]
        queue.append(now)
        self._trim_time_queue(queue, now)
        return len(queue)

    def prune(self, now: datetime) -> None:
        """Drop per-source bookkeeping whose events have all aged out.

        Behaviour-neutral: the queue dicts are defaultdicts, so a deleted entry
        is recreated on the source's next packet and is indistinguishable from
        one that had been trimmed to empty. Without this a flood of spoofed
        source addresses would grow the tables without bound, making the
        monitor itself a resource-exhaustion target.

        `arp_table` is deliberately exempt -- see `check_arp_conflict`.
        """
        stale_scans = [
            src_ip
            for src_ip, queue in self.scan_ports.items()
            if not queue or (now - queue[-1][0]).total_seconds() > self.window_seconds
        ]
        for src_ip in stale_scans:
            del self.scan_ports[src_ip]

        stale_dns = [
            src_ip
            for src_ip, queue in self.dns_requests.items()
            if not queue or (now - queue[-1]).total_seconds() > self.window_seconds
        ]
        for src_ip in stale_dns:
            del self.dns_requests[src_ip]

    def check_arp_conflict(self, ip_addr: str, mac_addr: str) -> Tuple[bool, str]:
        """Compare an IP's advertised MAC against the first one ever seen.

        The mapping never expires. That is a deliberate trade-off: an expiring
        table would let a spoofer simply stay quiet for one window and then
        claim the address unchallenged. The cost is that a legitimate MAC
        change for an IP (DHCP lease handed to a new device, NIC swap) is
        reported as a conflict -- acceptable for the monitoring sessions this
        tool is built for, and noted as a known limitation in the report.
        """
        previous_mac = self.arp_table.get(ip_addr)
        if previous_mac is None:
            self.arp_table[ip_addr] = mac_addr
            return False, ""
        if previous_mac != mac_addr:
            return True, previous_mac
        return False, previous_mac


class AlertLogger:
    def __init__(self, output_path: Path, print_alerts: bool = True) -> None:
        self.output_path = output_path
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.print_alerts = print_alerts
        self.alerts: List[dict] = []

    def log(self, alert_type: str, details: dict, timestamp: Optional[datetime] = None) -> None:
        ts = (timestamp or utc_now()).isoformat()
        payload = {
            "timestamp": ts,
            "type": alert_type,
            "details": details,
        }
        self.alerts.append(payload)
        if self.print_alerts:
            print(f"[ALERT] {ts} {alert_type} | {details}")

    def flush(self) -> None:
        self.output_path.write_text(json.dumps(self.alerts, indent=2), encoding="utf-8")


class DetectionEngine:
    def __init__(
        self,
        output: Path,
        scan_threshold: int,
        dns_threshold: int,
        window: int,
        print_alerts: bool = True,
    ) -> None:
        self.scan_threshold = scan_threshold
        self.dns_threshold = dns_threshold
        self.window = window
        self.state = WindowState(window_seconds=window)
        self.logger = AlertLogger(output_path=output, print_alerts=print_alerts)
        self.alert_cooldown: Dict[Tuple[str, str], datetime] = {}
        self.prune_interval = PRUNE_INTERVAL_PACKETS
        self.packets_seen = 0

    def prune(self, now: datetime) -> None:
        """Bound memory by dropping state for sources that have gone quiet."""
        self.state.prune(now)
        expired = [
            key
            for key, last_alert in self.alert_cooldown.items()
            if (now - last_alert).total_seconds() > self.window
        ]
        for key in expired:
            del self.alert_cooldown[key]

    def can_alert(self, key: Tuple[str, str], now: datetime) -> bool:
        prev = self.alert_cooldown.get(key)
        if prev is None or (now - prev).total_seconds() > self.window:
            self.alert_cooldown[key] = now
            return True
        return False

    def process_packet(self, packet, now: Optional[datetime] = None) -> None:  # noqa: ANN001
        event_time = now or utc_now()

        self.packets_seen += 1
        if self.packets_seen % self.prune_interval == 0:
            self.prune(event_time)

        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dport = int(packet[TCP].dport)
            tcp_flags = int(packet[TCP].flags) & TCP_CONTROL_BITS
            if is_private_ip(src_ip) and tcp_flags == TCP_SYN:
                unique_ports = self.state.add_scan_event(src_ip, dport, event_time)
                if len(unique_ports) >= self.scan_threshold and self.can_alert(
                    ("scan", src_ip), event_time
                ):
                    self.logger.log(
                        "possible_port_scan",
                        {
                            "source_ip": src_ip,
                            "unique_ports_in_window": len(unique_ports),
                            "window_seconds": self.window,
                        },
                        timestamp=event_time,
                    )

        if packet.haslayer(ARP):
            arp = packet[ARP]
            sender_ip = str(arp.psrc)
            sender_mac = str(arp.hwsrc)
            if sender_ip == "0.0.0.0" or sender_mac.lower() == "ff:ff:ff:ff:ff:ff":
                return
            conflict, old_mac = self.state.check_arp_conflict(sender_ip, sender_mac)
            if conflict and self.can_alert(("arp", sender_ip), event_time):
                self.logger.log(
                    "possible_arp_spoofing",
                    {
                        "ip": sender_ip,
                        "known_mac": old_mac,
                        "observed_mac": sender_mac,
                    },
                    timestamp=event_time,
                )

        if packet.haslayer(IP) and packet.haslayer(DNS) and packet[DNS].qr == 0:
            src_ip = packet[IP].src
            if not is_private_ip(src_ip):
                return
            dns_count = self.state.add_dns_event(src_ip, event_time)
            if dns_count >= self.dns_threshold and self.can_alert(("dns", src_ip), event_time):
                self.logger.log(
                    "dns_burst_anomaly",
                    {
                        "source_ip": src_ip,
                        "requests_in_window": dns_count,
                        "window_seconds": self.window,
                    },
                    timestamp=event_time,
                )

    def flush(self) -> None:
        self.logger.flush()
