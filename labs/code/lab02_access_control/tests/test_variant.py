import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from detector import DenialBurstDetector, NewPermissionDetector, VariantDetector
from mypolicy import CapabilityPolicy, build_marketplace_policy, objects_accessible_by

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


class ClockLog(AuditLog):
    def __init__(self) -> None:
        super().__init__()
        self.t = 0.0

    def _now(self) -> float:
        return self.t


def make():
    p = CapabilityPolicy()
    p.grant("alice", "doc1", R)
    p.grant("alice", "doc1", W)
    p.grant("bob", "doc2", R | W)
    return p


def test_grant_and_union_of_rights():
    p = make()
    assert p.evaluate("alice", "doc1", R | W).allowed
    assert p.capabilities_of("alice") == {"doc1": R | W}


def test_safe_default_unknown_subject_and_object():
    p = make()
    assert not p.evaluate("невідомий", "doc1", R).allowed
    d = p.evaluate("alice", "doc2", R)
    assert not d.allowed and "safe default" in d.reason


def test_partial_rights_are_not_enough():
    assert not make().evaluate("alice", "doc1", R | D).allowed


def test_revoke():
    p = make()
    p.revoke("alice", "doc1", W)
    assert p.evaluate("alice", "doc1", R).allowed
    assert not p.evaluate("alice", "doc1", W).allowed


def test_marketplace_size_matches_variant():
    p, subjects, objects = build_marketplace_policy()
    assert len(subjects) == 6 and len(set(objects)) == 29
    assert all(p.capabilities_of(s) for s in subjects)


def test_deny_overrides_grant():
    p = make()
    p.deny("alice", "doc1", W)
    d = p.evaluate("alice", "doc1", W)
    assert not d.allowed and "deny" in d.reason


def test_deny_blocks_only_its_right():
    p = make()
    p.deny("alice", "doc1", W)
    assert p.evaluate("alice", "doc1", R).allowed
    assert not p.evaluate("alice", "doc1", R | W).allowed


def test_deny_changes_marketplace_decision():
    p, _, _ = build_marketplace_policy()
    assert p.evaluate("seller_carol", "listing02", W).allowed
    assert not p.evaluate("seller_carol", "listing03", W).allowed
    assert p.evaluate("seller_carol", "listing03", R).allowed
    assert not p.evaluate("moderator_eve", "role_config", D).allowed
    assert p.evaluate("moderator_eve", "role_config", W).allowed


def test_complete_mediation_every_call_logged():
    p, subjects, objects = build_marketplace_policy()
    mon = ReferenceMonitor(p)
    calls = [(s, o, a) for s in subjects for o in objects[:5] for a in (R, W)]
    for s, o, a in calls:
        mon.check(s, o, a)
    entries = mon.audit.entries()
    assert len(entries) == len(calls)
    assert {e["allowed"] for e in entries} == {True, False}


def test_enforce_raises_on_denial():
    mon = ReferenceMonitor(make())
    mon.enforce("alice", "doc1", R)
    with pytest.raises(PermissionError, match="safe default"):
        mon.enforce("bob", "doc1", W)
    assert len(mon.audit.entries()) == 2


def test_capabilities_copy_cannot_tamper_policy():
    p = make()
    caps = p.capabilities_of("alice")
    caps["doc2"] = Permission.ADMIN
    assert not p.evaluate("alice", "doc2", R).allowed


def test_queries_are_dual():
    p, subjects, objects = build_marketplace_policy()
    for a in (R, W, D):
        for s in subjects:
            accessible = set(objects_accessible_by(p, s, objects, a))
            for o in objects:
                assert (s in subjects_with_access(p, subjects, o, a)) == (o in accessible)


def test_deny_removes_object_from_query():
    p = make()
    assert objects_accessible_by(p, "alice", ["doc1", "doc2"], R) == ["doc1"]
    p.deny("alice", "doc1", R)
    assert objects_accessible_by(p, "alice", ["doc1", "doc2"], R) == []


def _denials(log, who, count, step):
    mon = ReferenceMonitor(make(), log)
    for i in range(count):
        log.t = i * step
        mon.check(who, f"obj{i}", W)


def test_denial_burst_detected():
    log = ClockLog()
    _denials(log, "mallory", 5, step=2.0)
    alerts = DenialBurstDetector(threshold=5, window=60).scan(log)
    assert len(alerts) == 1 and "mallory" in alerts[0]


def test_denials_spread_over_time_not_detected():
    log = ClockLog()
    _denials(log, "mallory", 5, step=30.0)
    assert DenialBurstDetector(threshold=5, window=60).scan(log) == []


def test_denials_below_threshold_not_detected():
    log = ClockLog()
    _denials(log, "mallory", 4, step=1.0)
    assert DenialBurstDetector(threshold=5, window=60).scan(log) == []


def _baseline():
    mon = ReferenceMonitor(make())
    mon.check("alice", "doc1", R)
    mon.check("bob", "doc2", R)
    return mon.audit


def test_new_permission_detected_once():
    mon = ReferenceMonitor(make())
    mon.check("alice", "doc1", W)
    mon.check("alice", "doc1", W)
    alerts = NewPermissionDetector(_baseline()).scan(mon.audit)
    assert len(alerts) == 1 and "alice" in alerts[0] and "WRITE" in alerts[0]


def test_known_permission_and_denials_not_detected():
    mon = ReferenceMonitor(make())
    mon.check("alice", "doc1", R)
    mon.check("alice", "doc2", D)
    assert NewPermissionDetector(_baseline()).scan(mon.audit) == []


def test_variant_detector_reports_both_anomalies():
    log = ClockLog()
    _denials(log, "mallory", 6, step=1.0)
    ReferenceMonitor(make(), log).check("bob", "doc2", W)
    alerts = VariantDetector(_baseline(), threshold=5, window=60).scan(log)
    assert len(alerts) == 2
    assert alerts[0].startswith("сплеск відмов") and alerts[1].startswith("нове право")


def test_clean_log_has_no_alerts():
    mon = ReferenceMonitor(make())
    mon.check("alice", "doc1", R)
    mon.check("bob", "doc2", R)
    assert VariantDetector(_baseline()).scan(mon.audit) == []
    assert VariantDetector().scan(AuditLog()) == []
