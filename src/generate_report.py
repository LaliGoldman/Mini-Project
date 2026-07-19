from __future__ import annotations

import argparse
import html
from collections import Counter
from pathlib import Path
from typing import List

from summarize_logs import load_alerts, source_key

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
.cards{display:flex;gap:1rem;flex-wrap:wrap}
.card{border:1px solid #ddd;border-left:4px solid #c0392b;border-radius:8px;padding:1rem;flex:1;min-width:16rem}
.card .ts{color:#666;font-size:.85rem}
"""


def esc(value: object) -> str:
    return html.escape(str(value))


BAR_WIDTH = 260
BAR_HEIGHT = 16

METRIC_KEYS = {
    "possible_port_scan": "unique_ports_in_window",
    "dns_burst_anomaly": "requests_in_window",
}


def metric_value(alert: dict) -> int:
    key = METRIC_KEYS.get(alert.get("type", ""))
    if key is None:
        return 0
    try:
        return int((alert.get("details") or {}).get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def render_bar(value: float, scale: float) -> str:
    fraction = min(value / scale, 1.0) if scale > 0 else 0.0
    fill = round(BAR_WIDTH * fraction)
    return (
        f'<svg width="{BAR_WIDTH}" height="{BAR_HEIGHT}" role="img">'
        f'<rect width="{BAR_WIDTH}" height="{BAR_HEIGHT}" fill="#e8e8ee"/>'
        f'<rect width="{fill}" height="{BAR_HEIGHT}" fill="#c0392b"/>'
        "</svg>"
    )


def render_card(alert: dict, scale: int) -> str:
    alert_type = alert.get("type", "unknown")
    details = alert.get("details") or {}
    timestamp = esc(alert.get("timestamp", "?"))
    if alert_type == "possible_port_scan":
        value = metric_value(alert)
        body = (
            f"<p><strong>{esc(source_key(alert))}</strong> hit <strong>{value}</strong> "
            f"distinct destination ports within {esc(details.get('window_seconds', '?'))}s "
            "&mdash; at or above the scan threshold.</p>" + render_bar(value, scale)
        )
    elif alert_type == "dns_burst_anomaly":
        value = metric_value(alert)
        body = (
            f"<p><strong>{esc(source_key(alert))}</strong> sent <strong>{value}</strong> "
            f"DNS requests within {esc(details.get('window_seconds', '?'))}s "
            "&mdash; at or above the burst threshold.</p>" + render_bar(value, scale)
        )
    elif alert_type == "possible_arp_spoofing":
        body = (
            f"<p><strong>{esc(details.get('ip', '?'))}</strong> was known as "
            f"<code>{esc(details.get('known_mac', '?'))}</code> but was claimed by "
            f"<code>{esc(details.get('observed_mac', '?'))}</code> "
            "&mdash; IP&harr;MAC conflict.</p>"
        )
    else:
        items = "".join(
            f"<li><code>{esc(key)}</code>: {esc(value)}</li>" for key, value in details.items()
        )
        body = f"<ul>{items or '<li>no details recorded</li>'}</ul>"
    return (
        f'<article class="card"><h3>{esc(alert_type)}</h3>'
        f'<p class="ts">{timestamp}</p>{body}</article>'
    )


def render_cards(alerts: List[dict]) -> str:
    if not alerts:
        return ""
    by_type: dict[str, List[dict]] = {}
    for alert in alerts:
        by_type.setdefault(alert.get("type", "unknown"), []).append(alert)
    sections = []
    for alert_type, group in sorted(by_type.items()):
        scale = max((metric_value(alert) for alert in group), default=0)
        cards = "".join(render_card(alert, scale) for alert in group)
        sections.append(
            f'<section><h2>{esc(alert_type)}</h2><div class="cards">{cards}</div></section>'
        )
    return "\n".join(sections)


def evidence_summary(alert: dict) -> str:
    details = alert.get("details") or {}
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
        body = render_summary(alerts) + render_cards(alerts) + render_timeline(alerts)
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


DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "logs" / "pcap_alerts.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "logs" / "report.html"


def run(paths: List[Path], output: Path) -> None:
    alerts: List[dict] = []
    for path in paths:
        alerts.extend(load_alerts(path))
    report = build_report(alerts, [path.name for path in paths])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"[*] Report written to {output} ({len(alerts)} alerts)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render alert JSON logs as a self-contained HTML report"
    )
    parser.add_argument(
        "logs",
        nargs="*",
        type=Path,
        default=[DEFAULT_INPUT],
        help="Alert JSON files (default: logs/pcap_alerts.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output HTML path (default: logs/report.html)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(paths=args.logs, output=args.output)
