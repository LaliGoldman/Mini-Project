from __future__ import annotations

import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple

from scapy.all import ARP, DNS, IP, TCP  # type: ignore


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

    def check_arp_conflict(self, ip_addr: str, mac_addr: str) -> Tuple[bool, str]:
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

    def can_alert(self, key: Tuple[str, str], now: datetime) -> bool:
        prev = self.alert_cooldown.get(key)
        if prev is None or (now - prev).total_seconds() > self.window:
            self.alert_cooldown[key] = now
            return True
        return False

    def process_packet(self, packet, now: Optional[datetime] = None) -> None:  # noqa: ANN001
        event_time = now or utc_now()

        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dport = int(packet[TCP].dport)
            tcp_flags = int(packet[TCP].flags)
            if is_private_ip(src_ip) and tcp_flags == 0x02:
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

        if packet.haslayer(IP) and packet.haslayer(DNS):
            src_ip = packet[IP].src
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
