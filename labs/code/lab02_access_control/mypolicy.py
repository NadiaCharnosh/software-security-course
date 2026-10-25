from __future__ import annotations

from typing import Iterable

from accesscontrol.monitor import Decision, Permission, Policy


class CapabilityPolicy(Policy):
    def __init__(self) -> None:
        self._caps: dict[str, dict[str, Permission]] = {}
        self._deny: dict[str, dict[str, Permission]] = {}

    def grant(self, who: str, obj: str, perm: Permission) -> None:
        row = self._caps.setdefault(who, {})
        row[obj] = row.get(obj, Permission.NONE) | perm

    def revoke(self, who: str, obj: str, perm: Permission) -> None:
        row = self._caps.get(who, {})
        rest = row.get(obj, Permission.NONE) & ~perm
        if rest:
            row[obj] = rest
        else:
            row.pop(obj, None)

    def deny(self, who: str, obj: str, perm: Permission) -> None:
        row = self._deny.setdefault(who, {})
        row[obj] = row.get(obj, Permission.NONE) | perm

    def capabilities_of(self, subject: str) -> dict[str, Permission]:
        return dict(self._caps.get(subject, {}))

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        if action == Permission.NONE:
            return Decision(False, "порожня дія (safe default)")
        denied = self._deny.get(subject, {}).get(obj, Permission.NONE)
        if action & denied:
            return Decision(False, "заборонний запис (deny) має пріоритет")
        effective = self._caps.get(subject, {}).get(obj, Permission.NONE)
        if action & effective == action:
            return Decision(True, "надано")
        return Decision(False, "немає квитка на цю дію (safe default)")


def objects_accessible_by(policy: Policy, subject: str, objects: Iterable[str],
                          action: Permission) -> list[str]:
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]


SUBJECTS = ["buyer_alice", "buyer_bob", "seller_carol", "seller_dave",
            "moderator_eve", "support_frank"]

LISTINGS = [f"listing{i:02d}" for i in range(1, 13)]
ORDERS = [f"order{i:02d}" for i in range(1, 9)]
PHOTOS = [f"photo{i:02d}" for i in range(1, 6)]
REPORTS = ["report01", "report02"]
SYSTEM = ["users_db", "role_config"]

OBJECTS = LISTINGS + ORDERS + PHOTOS + REPORTS + SYSTEM

R, W, D, ADMIN = Permission.READ, Permission.WRITE, Permission.DELETE, Permission.ADMIN


def build_marketplace_policy() -> tuple[CapabilityPolicy, list[str], list[str]]:
    p = CapabilityPolicy()

    for buyer, own_orders in (("buyer_alice", ORDERS[:3]), ("buyer_bob", ORDERS[3:5])):
        for obj in LISTINGS + PHOTOS:
            p.grant(buyer, obj, R)
        for obj in own_orders:
            p.grant(buyer, obj, R | W)

    for seller, own, photos, orders in (
        ("seller_carol", LISTINGS[:6], PHOTOS[:3], ["order01", "order02", "order04"]),
        ("seller_dave", LISTINGS[6:], PHOTOS[3:], ["order03", "order05"]),
    ):
        for obj in LISTINGS:
            p.grant(seller, obj, R)
        for obj in own + photos:
            p.grant(seller, obj, ADMIN)
        for obj in orders:
            p.grant(seller, obj, R)

    for obj in LISTINGS + PHOTOS:
        p.grant("moderator_eve", obj, ADMIN)
    for obj in REPORTS:
        p.grant("moderator_eve", obj, R | W)
    p.grant("moderator_eve", "users_db", R)
    p.grant("moderator_eve", "role_config", ADMIN)

    for obj in ORDERS:
        p.grant("support_frank", obj, R | W)
    for obj in REPORTS:
        p.grant("support_frank", obj, R)
    p.grant("support_frank", "users_db", R)

    p.deny("seller_carol", "listing03", W)
    p.deny("moderator_eve", "role_config", D)
    p.deny("support_frank", "users_db", R)
    p.deny("buyer_bob", "listing09", R)

    return p, list(SUBJECTS), list(OBJECTS)
