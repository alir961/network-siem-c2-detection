"""
Structured JSON logger for SIEM alerts.
"""
import json
import time
from pathlib import Path


class SIEMLogger:
    SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def __init__(self, log_path: str) -> None:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        self._path = log_path

    def log(
        self,
        rule: str,
        severity: str,
        src: str,
        dst: str,
        details: dict,
    ) -> dict:
        assert severity in self.SEVERITIES, f"Unknown severity: {severity}"
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rule":      rule,
            "severity":  severity,
            "src":       src,
            "dst":       dst,
            "details":   details,
        }
        with open(self._path, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry
