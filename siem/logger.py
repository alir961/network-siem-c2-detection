"""
Structured JSON Lines logger for SIEM alerts (ready for ingestion by jq, Elastic, Splunk…).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class SIEMLogger:
    def __init__(self, log_path: str) -> None:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self.path = log_path

    def log(self, alert: dict, epoch: float | None = None) -> dict:
        """Append one alert. `epoch` is the event time (packet time in replay mode)."""
        if alert["severity"] not in SEVERITIES:
            raise ValueError(f"Unknown severity: {alert['severity']}")
        entry = {
            "timestamp": (datetime.fromtimestamp(epoch, timezone.utc) if epoch is not None
                          else datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            **alert,
        }
        with open(self.path, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry
