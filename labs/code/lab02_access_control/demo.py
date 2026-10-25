from __future__ import annotations

import sys

from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from detector import VariantDetector
from mypolicy import build_marketplace_policy, objects_accessible_by

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE

EXPECTED = [
    ("buyer_alice", "listing01", R, True, "покупець читає каталог"),
    ("buyer_alice", "order01", W, True, "власне замовлення"),
    ("buyer_alice", "order04", R, False, "чуже замовлення — safe default"),
    ("buyer_bob", "listing08", R, True, "покупець читає каталог"),
    ("buyer_bob", "listing09", R, False, "deny: покупця заблоковано продавцем"),
    ("seller_carol", "listing02", W, True, "власне оголошення (ADMIN)"),
    ("seller_carol", "listing03", W, False, "deny: оголошення заблоковане"),
    ("seller_carol", "listing03", R, True, "deny стосується лише WRITE"),
    ("seller_carol", "listing07", W, False, "чуже оголошення — safe default"),
    ("seller_dave", "photo04", D, True, "власне фото (ADMIN)"),
    ("moderator_eve", "role_config", W, True, "модератор змінює ролі"),
    ("moderator_eve", "role_config", D, False, "deny: видалення конфігурації ролей"),
    ("support_frank", "order06", W, True, "підтримка редагує замовлення"),
    ("support_frank", "users_db", R, False, "deny: доступ до ПДн закрито"),
    ("support_frank", "role_config", W, False, "немає квитка — safe default"),
]


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> None:
    policy, subjects, objects = build_marketplace_policy()
    print(f"Суб'єктів: {len(subjects)}, об'єктів: {len(objects)}")

    section("Крок 3. Очікувані та фактичні рішення evaluate")
    print(f"{'суб’єкт':<14} {'об’єкт':<12} {'дія':<7} {'очік.':<6} {'факт.':<6} збіг  причина")
    mismatches = 0
    for s, o, a, exp, _ in EXPECTED:
        d = policy.evaluate(s, o, a)
        ok = d.allowed == exp
        mismatches += not ok
        print(f"{s:<14} {o:<12} {a.name:<7} {str(exp):<6} {str(d.allowed):<6} "
              f"{'так' if ok else 'НІ':<5} {d.reason}")
    print(f"Розбіжностей: {mismatches}")

    section("Крок 4. Повне посередництво: серія звернень через монітор")
    mon = ReferenceMonitor(policy)
    for s, o, a, _, _ in EXPECTED:
        mon.check(s, o, a)
    try:
        mon.enforce("buyer_bob", "role_config", W)
    except PermissionError as e:
        print("відмову перехоплено:", e)
    calls = len(EXPECTED) + 1
    entries = mon.audit.entries()
    print(f"викликів монітора: {calls}, записів у журналі: {len(entries)}, "
          f"дозволів: {sum(e['allowed'] for e in entries)}, "
          f"відмов: {sum(not e['allowed'] for e in entries)}")
    print("Фрагмент AuditLog.dump():")
    print("\n".join(mon.audit.dump().splitlines()[4:9]))

    section("Крок 7. Запити «хто має доступ» і «до чого має доступ»")
    print("хто читає listing09:", subjects_with_access(policy, subjects, "listing09", R))
    print("хто пише в listing03:", subjects_with_access(policy, subjects, "listing03", W))
    print("хто читає users_db:", subjects_with_access(policy, subjects, "users_db", R))
    print("що змінює seller_carol:", objects_accessible_by(policy, "seller_carol", objects, W))
    print("що читає buyer_bob:", objects_accessible_by(policy, "buyer_bob", objects, R))
    print("квитки moderator_eve на role_config:",
          policy.capabilities_of("moderator_eve")["role_config"])
    consistent = all(
        (s in subjects_with_access(policy, subjects, o, a))
        == (o in objects_accessible_by(policy, s, objects, a))
        for a in (R, W, D) for s in subjects for o in objects)
    print("узгодженість запитів на всій матриці 6×29×3:", consistent)

    section("Крок 5. Детектор аномалій (А1 — сплеск відмов, А5 — нові права)")
    base = ReferenceMonitor(policy)
    for s, o, a in [("buyer_alice", "listing01", R), ("buyer_alice", "order01", W),
                    ("buyer_bob", "listing02", R), ("buyer_bob", "order04", W),
                    ("seller_carol", "listing01", R), ("seller_carol", "listing02", W),
                    ("seller_dave", "listing07", W), ("moderator_eve", "report01", R),
                    ("moderator_eve", "listing05", W), ("support_frank", "order02", W),
                    ("support_frank", "report02", R)]:
        base.check(s, o, a)
    detector = VariantDetector(base.audit, threshold=5, window=60)

    clean = ReferenceMonitor(policy)
    for s, o, a in [("buyer_alice", "listing04", R), ("seller_carol", "listing05", W),
                    ("support_frank", "order07", W), ("buyer_bob", "listing09", R)]:
        clean.check(s, o, a)
    print("чистий журнал:", detector.scan(clean.audit))

    attack = ReferenceMonitor(policy, AuditLog())
    for o in ("order01", "order02", "order03", "order06", "order07", "order08"):
        attack.check("buyer_bob", o, W)
    attack.check("seller_carol", "listing04", D)
    print("журнал з аномаліями:")
    for alert in detector.scan(attack.audit):
        print("  ALERT:", alert)


if __name__ == "__main__":
    main()
