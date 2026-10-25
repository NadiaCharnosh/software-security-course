from __future__ import annotations

import collections
from typing import Iterable

from accesscontrol.monitor import AnomalyDetector, AuditLog


def _records(source: AuditLog | Iterable[dict]) -> list[dict]:
    return source.entries() if isinstance(source, AuditLog) else list(source)


def _rights(action: str) -> list[str]:
    return [a for a in action.split("|") if a]


class DenialBurstDetector(AnomalyDetector):
    def __init__(self, threshold: int = 5, window: float = 60.0) -> None:
        self.threshold = threshold
        self.window = window

    def scan(self, log: AuditLog) -> list[str]:
        denials: dict[str, list[float]] = collections.defaultdict(list)
        for r in log.entries():
            if not r["allowed"]:
                denials[r["subject"]].append(r["ts"])

        alerts: list[str] = []
        for subject, times in sorted(denials.items()):
            times.sort()
            start, peak = 0, 0
            for end, t in enumerate(times):
                while t - times[start] > self.window:
                    start += 1
                peak = max(peak, end - start + 1)
            if peak >= self.threshold:
                alerts.append(f"сплеск відмов: {subject} — {peak} відмов "
                              f"за {self.window:g} с (поріг {self.threshold})")
        return alerts


class NewPermissionDetector(AnomalyDetector):
    def __init__(self, baseline: AuditLog | Iterable[dict] = ()) -> None:
        self.baseline = {(r["subject"], right)
                         for r in _records(baseline) if r["allowed"]
                         for right in _rights(r["action"])}

    def scan(self, log: AuditLog) -> list[str]:
        seen = set(self.baseline)
        alerts: list[str] = []
        for r in log.entries():
            if not r["allowed"]:
                continue
            for right in _rights(r["action"]):
                if (r["subject"], right) not in seen:
                    seen.add((r["subject"], right))
                    alerts.append(f"нове право: {r['subject']} уперше використав "
                                  f"{right} (об'єкт {r['object']})")
        return alerts


class VariantDetector(AnomalyDetector):
    def __init__(self, baseline: AuditLog | Iterable[dict] = (),
                 threshold: int = 5, window: float = 60.0) -> None:
        self.burst = DenialBurstDetector(threshold, window)
        self.new_rights = NewPermissionDetector(baseline)

    def scan(self, log: AuditLog) -> list[str]:
        return self.burst.scan(log) + self.new_rights.scan(log)
