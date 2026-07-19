from __future__ import annotations

import html
from collections import Counter
from typing import List

from summarize_logs import source_key

CSS = """
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#222}
header p{color:#666}
.tiles{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.tile{border:1px solid #ddd;border-radius:8px;padding:1rem;flex:1;min-width:12rem}
.tile h2{margin:0;font-size:2rem}
.tile ul{margin:.5rem 0 0;padding-left:1.2rem}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}
.empty{color:#666;font-style:italic}
code{background:#f4f4f6;padding:0 .25rem;border-radius:4px}
"""


def esc(value: object) -> str:
    return html.escape(str(value))


def evidence_summary(alert: dict) -> str:
    details = alert.get("details", {})
    alert_type = alert.get("type", "unknown")
    if alert_type == "possible_port_scan":
        return (
            f"{details.get('unique_ports_in_window', '?')} unique ports "
            f"in {details.get('window_seconds', '?')}s window"
        )
    if alert_type == "dns_burst_anomaly":
        return (
            f"{details.get('requests_in_window', '?')} DNS requests "
            f"in {details.get('window_seconds', '?')}s window"
        )
    if alert_type == "possible_arp_spoofing":
        return (
            f"{details.get('ip', '?')} changed "
            f"{details.get('known_mac', '?')} -> {details.get('observed_mac', '?')}"
        )
    return ", ".join(f"{key}={value}" for key, value in details.items()) or "no details"


def render_summary(alerts: List[dict]) -> str:
    by_type = Counter(alert.get("type", "unknown") for alert in alerts)
    by_source = Counter(source_key(alert) for alert in alerts)
    type_items = "".join(
        f"<li><code>{esc(alert_type)}</code>: {count}</li>"
        for alert_type, count in sorted(by_type.items())
    )
    source_items = "".join(
        f"<li><code>{esc(source)}</code>: {count}</li>"
        for source, count in sorted(by_source.items(), key=lambda item: (-item[1], item[0]))
    )
    return (
        '<section class="tiles">'
        f'<div class="tile"><h2>{len(alerts)}</h2><p>total alerts</p></div>'
        f'<div class="tile"><h3>By type</h3><ul>{type_items or "<li>(none)</li>"}</ul></div>'
        f'<div class="tile"><h3>By source</h3><ul>{source_items or "<li>(none)</li>"}</ul></div>'
        "</section>"
    )


def render_timeline(alerts: List[dict]) -> str:
    if not alerts:
        return ""
    rows = "".join(
        f"<tr><td>{esc(alert.get('timestamp', '?'))}</td>"
        f"<td><code>{esc(alert.get('type', 'unknown'))}</code></td>"
        f"<td>{esc(source_key(alert))}</td>"
        f"<td>{esc(evidence_summary(alert))}</td></tr>"
        for alert in sorted(alerts, key=lambda alert: str(alert.get("timestamp", "")))
    )
    return (
        "<section><h2>Timeline</h2><table>"
        "<thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></section>"
    )


def build_report(alerts: List[dict], source_names: List[str]) -> str:
    sources = ", ".join(esc(name) for name in source_names)
    if alerts:
        body = render_summary(alerts) + render_timeline(alerts)
    else:
        body = render_summary(alerts) + '<p class="empty">No alerts in the provided logs.</p>'
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        "<title>Network Anomaly Report</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body>\n"
        "<header><h1>Network Anomaly Monitor &mdash; Alert Report</h1>"
        f"<p>Generated from: {sources}</p></header>\n"
        f"{body}\n</body>\n</html>\n"
    )
