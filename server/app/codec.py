"""Encodage sur le fil : les champs binaires (bytea) transitent en base64 dans
le JSON. Le hachage de chaîne est blake2b-256 (hashlib, pas de crypto tierce)."""

from __future__ import annotations

import base64
import hashlib


def b64e(data: bytes | memoryview | None) -> str | None:
    if data is None:
        return None
    return base64.b64encode(bytes(data)).decode()


def b64d(s: str | None) -> bytes | None:
    if s is None:
        return None
    return base64.b64decode(s)


def blake2b256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()
