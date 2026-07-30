"""Vérification serveur de la chaîne d'octrois — « confort » uniquement (SPEC §7).

Le serveur vérifie la *forme* : seq incrémental, prev chaîné, signature valide,
signataire connu. Il n'a AUCUNE autorité sur la politique (qui peut coopter
qui) : c'est le client qui rejoue et revérifie tout. Le CBOR est décodé en
lecture seule et jamais réencodé — on stocke les octets exacts reçus.
"""

from __future__ import annotations

import uuid

import cbor2
import nacl.exceptions
import nacl.signing

from .codec import blake2b256


class GrantRejected(Exception):
    """Déclaration mal formée — rejetée par le serveur (400)."""


def verify_structural(
    *,
    group_id: uuid.UUID,
    seq: int,
    stmt: bytes,
    sig: bytes,
    signer_ed25519_pub: bytes,
    expected_seq: int,
    prev_hash: bytes | None,
) -> None:
    """Lève GrantRejected si la déclaration ne respecte pas la forme attendue.

    Ne dit RIEN de la légitimité (le signataire est-il membre, la politique
    est-elle respectée) : cette autorité est côté client (SPEC §7, test §11.4).
    """
    # 1. seq strictement incrémental
    if seq != expected_seq:
        raise GrantRejected(f"seq attendu {expected_seq}, reçu {seq}")

    # 2. signature valide sur les octets exacts
    try:
        nacl.signing.VerifyKey(signer_ed25519_pub).verify(stmt, sig)
    except nacl.exceptions.BadSignatureError as exc:
        raise GrantRejected(f"signature invalide: {exc}") from exc

    # 3. CBOR décodable et cohérent (lecture seule, jamais réencodé)
    try:
        decoded = cbor2.loads(stmt)
    except Exception as exc:  # noqa: BLE001 — tout échec de décodage = malformé
        raise GrantRejected(f"CBOR illisible: {exc}") from exc

    if not isinstance(decoded, dict):
        raise GrantRejected("le stmt n'est pas une map CBOR")
    if decoded.get("v") != 1:
        raise GrantRejected(f"version de stmt inconnue: {decoded.get('v')!r}")
    if decoded.get("action") not in ("found", "add", "remove"):
        raise GrantRejected(f"action inconnue: {decoded.get('action')!r}")
    if decoded.get("group") != group_id.bytes:
        raise GrantRejected("le groupe du stmt ne correspond pas à l'URL")

    # 4. chaînage : prev pointe le hash du stmt précédent (null au seq 0)
    if decoded.get("prev") != prev_hash:
        raise GrantRejected("prev ne chaîne pas le stmt précédent")

    # 5. au seq 0, seule une fondation est acceptée
    if seq == 0 and decoded.get("action") != "found":
        raise GrantRejected("le premier maillon doit être une fondation")


def hash_stmt(stmt: bytes) -> bytes:
    return blake2b256(stmt)
