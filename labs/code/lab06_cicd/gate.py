"""Критерій проходження (quality gate) — КАРКАС для лабораторної роботи 6.

Читає звіти SAST і завершується з ненульовим кодом, якщо порушено умову варіанта.
"""
from __future__ import annotations

import json
import os
import sys


def load(path: str) -> dict | None:
    """Читає JSON-звіт. Повертає None, якщо звіту немає або його пошкоджено."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def bandit_high(report: dict) -> int:
    return sum(1 for r in report.get("results", [])
               if r.get("issue_severity") == "HIGH")


def main() -> int:
    bandit = load("bandit.json")
    if bandit is None:
        # Відсутній або пошкоджений звіт означає збій сканера, а не «0 знахідок».
        # Критерій має відмовляти в разі збою (fail closed): у конвеєрі сканер
        # запускається з `|| true`, тож інакше його падіння непомітно пропустило б
        # вразливий код у складання.
        print("::error::Quality gate: звіт bandit.json відсутній або пошкоджений — складання заблоковано")
        return 1
    high = bandit_high(bandit)
    print(f"Знахідок Bandit рівня HIGH: {high}")
    # TODO(варіант): реалізувати саме той критерій, що зазначений у завданні
    # (наприклад, блокувати за появи НОВИХ знахідок відносно базової лінії,
    # або за вразливої залежності з CVSS >= 7.0, або за секрету в діффі).
    threshold = int(os.environ.get("MAX_HIGH", "0"))
    if high > threshold:
        print(f"::error::Quality gate: {high} знахідок HIGH перевищує поріг {threshold}")
        return 1
    print("Quality gate: пройдено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
