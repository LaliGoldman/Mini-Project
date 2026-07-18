from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable, List


def load_alerts(path: Path) -> List[dict]:
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array in {path}")
    return data


def source_key(alert: dict) -> str:
    details = alert.get("details", {})
    return str(details.get("source_ip") or details.get("ip") or "unknown")


def summarize_file(path: Path) -> dict:
    alerts = load_alerts(path)
    by_type = Counter(alert.get("type", "unknown") for alert in alerts)
    by_source = Counter(source_key(alert) for alert in alerts)
    return {
        "file": str(path),
        "total_alerts": len(alerts),
        "by_type": dict(by_type),
        "by_source": dict(by_source),
        "alerts": alerts,
    }


def print_summary(summary: dict) -> None:
    print(f"\n=== {summary['file']} ===")
    print(f"Total alerts: {summary['total_alerts']}")
    print("By type:")
    if summary["by_type"]:
        for alert_type, count in sorted(summary["by_type"].items()):
            print(f"  - {alert_type}: {count}")
    else:
        print("  (none)")
    print("By source IP:")
    if summary["by_source"]:
        for ip_addr, count in sorted(summary["by_source"].items(), key=lambda x: (-x[1], x[0])):
            print(f"  - {ip_addr}: {count}")
    else:
        print("  (none)")


def export_csv(summaries: Iterable[dict], csv_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source_file", "timestamp", "type", "source_ip", "details_json"])
        for summary in summaries:
            for alert in summary["alerts"]:
                writer.writerow(
                    [
                        summary["file"],
                        alert.get("timestamp", ""),
                        alert.get("type", ""),
                        source_key(alert),
                        json.dumps(alert.get("details", {}), ensure_ascii=False),
                    ]
                )


def export_summary_csv(summaries: Iterable[dict], csv_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["source_file", "alert_type", "count"])
        for summary in summaries:
            for alert_type, count in sorted(summary["by_type"].items()):
                writer.writerow([summary["file"], alert_type, count])


def run(paths: List[Path], csv_path: Path | None, summary_csv_path: Path | None) -> None:
    summaries = [summarize_file(path) for path in paths]
    for summary in summaries:
        print_summary(summary)

    if len(summaries) > 1:
        print("\n=== Comparison ===")
        for summary in summaries:
            print(
                f"{Path(summary['file']).name}: "
                f"{summary['total_alerts']} alerts | types={summary['by_type']}"
            )

    if csv_path:
        export_csv(summaries, csv_path)
        print(f"\n[*] Detailed CSV written to {csv_path}")

    if summary_csv_path:
        export_summary_csv(summaries, summary_csv_path)
        print(f"[*] Summary CSV written to {summary_csv_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize anomaly alert JSON logs")
    parser.add_argument(
        "logs",
        nargs="+",
        type=Path,
        help="One or more alert JSON files (example: logs/run_a.json logs/run_b.json)",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Optional path for detailed alerts CSV export",
    )
    parser.add_argument(
        "--summary-csv",
        type=Path,
        default=Path("logs/summary_by_type.csv"),
        help="Path for summary CSV (counts by type per file)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(paths=args.logs, csv_path=args.csv, summary_csv_path=args.summary_csv)
