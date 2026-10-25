"""Тести ЛР1: калькулятор CVSS, вимоги варіанта та узгодженість зі звітом."""
import re
from pathlib import Path

import pytest

from cvss import base_score
from scoring import level, threats

REPORT = Path(__file__).resolve().parents[2] / "звіт_лр1" / "threat_model.md"
FOCUS = "E"
MIN_THREATS = 12
MIN_HIGH_RISK = 3


def _section(text: str, number: int) -> str:
    start = text.index(f"## {number}.")
    end = text.find("\n## ", start + 1)
    return text[start:end]


@pytest.fixture(scope="module")
def report() -> str:
    return REPORT.read_text(encoding="utf-8")


def test_control_vector():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_control_question_6():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 6.5


@pytest.mark.parametrize("score, expected", [
    (0.0, "немає"), (3.9, "низький"), (4.0, "середній"),
    (6.9, "середній"), (7.0, "високий"), (8.9, "високий"), (9.0, "критичний"),
], ids=["0.0", "3.9", "4.0", "6.9", "7.0", "8.9", "9.0"])
def test_level_boundaries(score, expected):
    assert level(score) == expected


def test_more_privileges_lower_score():
    v = "CVSS:3.1/AV:N/AC:L/PR:{}/UI:N/S:U/C:H/I:H/A:H"
    assert base_score(v.format("N")) > base_score(v.format("L")) > base_score(v.format("H"))


def test_min_threats():
    assert len(threats) >= MIN_THREATS


def test_min_high_risk():
    high = [t for t, v in threats.items() if base_score(v) >= 7.0]
    assert len(high) >= MIN_HIGH_RISK


def test_focus_category_dominates(report):
    cats = re.findall(r"^\| T-\d+ \|[^|]+\| \**([STRIDE])\** \|", _section(report, 3), re.M)
    assert len(cats) == len(threats)
    counts = {c: cats.count(c) for c in set(cats)}
    assert all(counts[FOCUS] > n for c, n in counts.items() if c != FOCUS)


def test_report_matches_scoring(report):
    rows = re.findall(r"^\| \**(T-\d+)\** \| (CVSS:3\.1/\S+) \| \**([\d.]+)\** \|",
                      _section(report, 4), re.M)
    assert {tid: (vec, float(s)) for tid, vec, s in rows} == {
        tid: (vec, base_score(vec)) for tid, vec in threats.items()
    }
