"""Зберігання та перевірка паролів — КАРКАС для лабораторної роботи 3.

Здобувач реалізує функцію зберігання за KDF свого варіанта
(Argon2id / scrypt / bcrypt / PBKDF2), додає «перець» і перевірку за сталий час.
"""
from __future__ import annotations

import hashlib
import hmac
import os


PEPPER = os.environ.get("AUTH_PEPPER", "").encode()


# ВРАЗЛИВИЙ зразок (для порівняння у звіті) — НЕ використовувати:
def hash_password_insecure(password: str) -> str:
    # ВРАЗЛИВО: швидка хеш-функція без солі — вразлива до райдужних таблиць.
    return hashlib.sha256(password.encode()).hexdigest()


def hash_password(password: str) -> str:
    """БЕЗПЕЧНО: реалізуйте зберігання за KDF свого варіанта.

    Вимоги:
      – унікальна випадкова сіль на кожен пароль (>= 16 байтів);
      – «перець» із секретного сховища (тут — змінна середовища PEPPER);
      – параметри KDF за чинними рекомендаціями (RFC 9106 для Argon2id).
    """
    # TODO(варіант): повернути рядок формату, що містить параметри, сіль і хеш.
    raise NotImplementedError("Реалізуйте hash_password за KDF свого варіанта")


def verify_password(stored: str, password: str) -> bool:
    """Перевірка пароля. Порівняння тегів — лише за сталий час (hmac.compare_digest)."""
    # TODO(варіант): відновити параметри й сіль зі `stored`, обчислити хеш,
    # порівняти за сталий час.
    raise NotImplementedError("Реалізуйте verify_password")


def _peppered(data: bytes) -> bytes:
    return hmac.new(PEPPER, data, hashlib.sha256).digest() if PEPPER else data
