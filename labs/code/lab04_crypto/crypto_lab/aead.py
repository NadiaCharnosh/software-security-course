"""Симетричне шифрування — КАРКАС для лабораторної роботи 4.

Здобувач реалізує шифрування за AEAD свого варіанта і демонструє наслідки
двох типових помилок зі свого завдання (ECB, повторний nonce тощо).
"""
from __future__ import annotations


def encrypt(plaintext: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """БЕЗПЕЧНО: реалізуйте автентифіковане шифрування (AES-GCM / ChaCha20-Poly1305).

    Вимоги:
      – унікальний nonce на кожне повідомлення (лекція 10);
      – прив'язка асоційованих даних;
      – повернення nonce разом із шифротекстом і тегом.
    """
    # TODO(варіант): використати cryptography.hazmat.primitives.ciphers.aead
    raise NotImplementedError("Реалізуйте encrypt за AEAD свого варіанта")


def decrypt(blob: bytes, key: bytes, associated: bytes = b"") -> bytes:
    # TODO(варіант): перевірити тег автентичності; за розбіжності — підняти виняток.
    raise NotImplementedError("Реалізуйте decrypt")
