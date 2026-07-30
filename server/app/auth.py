"""Authentification par défi-réponse Ed25519 (SPEC §8) — pas de mot de passe
côté serveur, ce qui préfigure directement la carte à puce.

Le serveur émet un nonce ; le client le signe avec sa clé Ed25519 ; le serveur
vérifie contre la clé publique enrôlée et pose un cookie de session signé.
"""

from __future__ import annotations

import secrets
import time
import uuid

import nacl.exceptions
import nacl.signing
from fastapi import Depends, HTTPException, Request

# Défis en mémoire : {matricule: (nonce, expiration)}. Suffisant pour un dev
# mono-réplica ; une vraie prod les mettrait dans un store partagé à TTL.
_challenges: dict[str, tuple[bytes, float]] = {}
_CHALLENGE_TTL = 120.0


def new_challenge(matricule: str) -> bytes:
    nonce = secrets.token_bytes(32)
    _challenges[matricule] = (nonce, time.monotonic() + _CHALLENGE_TTL)
    return nonce


def consume_challenge(matricule: str) -> bytes | None:
    entry = _challenges.pop(matricule, None)
    if entry is None:
        return None
    nonce, exp = entry
    if time.monotonic() > exp:
        return None
    return nonce


def verify_response(ed25519_pub: bytes, nonce: bytes, sig: bytes) -> bool:
    try:
        nacl.signing.VerifyKey(ed25519_pub).verify(nonce, sig)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


class SessionMember:
    def __init__(self, member_id: uuid.UUID, matricule: str, key_id: uuid.UUID):
        self.member_id = member_id
        self.matricule = matricule
        self.key_id = key_id


def current_member(request: Request) -> SessionMember:
    """Dépendance : exige une session ouverte. 401 sinon."""
    sess = request.session
    if "member_id" not in sess:
        raise HTTPException(status_code=401, detail="non authentifié")
    return SessionMember(uuid.UUID(sess["member_id"]), sess["matricule"], uuid.UUID(sess["key_id"]))


CurrentMember = Depends(current_member)
