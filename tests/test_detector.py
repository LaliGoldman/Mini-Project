from __future__ import annotations

import json
from pathlib import Path

import pytest

import detector


def test_flush_runs_when_sniff_is_interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_sniff(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(detector, "sniff", broken_sniff)
    output = tmp_path / "alerts.json"

    with pytest.raises(KeyboardInterrupt):
        detector.run(
            interface="fake0",
            duration=1,
            output=output,
            scan_threshold=20,
            dns_threshold=30,
            window=10,
        )

    assert output.exists(), "alerts file must be written even if capture is interrupted"
    assert json.loads(output.read_text(encoding="utf-8")) == []
