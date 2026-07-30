"""Lot 0 — cœur du modèle E2EE par groupes.

Ce module contient *toute* la cryptographie et *toute* l'autorité de la
composition du groupe (le rejeu de chaîne). Il ne connaît ni le réseau ni le
stockage : il manipule des octets et des objets clairs. Le « serveur »
(store.py) n'importe aucune de ces fonctions — il ne fait que ranger des blobs.

Correspondance avec la SPEC §9 : les quatre fonctions qui manipulent du secret
sont ``unlock_keyblob``, ``open_epoch``, ``seal_note`` et ``open_note``.
``unlock_keyblob`` est le seul point que la carte à puce remplacera.
"""

from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass
from typing import Optional

import cbor2
import nacl.bindings as sodium
import nacl.hash
import nacl.encoding
import nacl.signing
import nacl.utils
from pyrage import decrypt as age_decrypt
from pyrage import encrypt as age_encrypt
from pyrage import passphrase as age_passphrase
from pyrage import x25519

KEYBLOB_VERSION = 1
STMT_VERSION = 1
GK_LEN = 32
CEK_LEN = 32
NONCE_LEN = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24


# --------------------------------------------------------------------------- #
# Hachage — blake2b-256, la seule fonction de hachage du projet.
# --------------------------------------------------------------------------- #
def blake2b256(data: bytes) -> bytes:
    return nacl.hash.blake2b(
        data, digest_size=32, encoder=nacl.encoding.RawEncoder
    )


# --------------------------------------------------------------------------- #
# Niveau keyblob (SPEC §3, §6) — identité age + clé de signature Ed25519,
# chiffrées sous la passphrase en mode age/scrypt. Aucune dérivation maison.
# --------------------------------------------------------------------------- #
@dataclass
class Keyblob:
    """Le secret déverrouillé d'un membre, en mémoire uniquement."""

    age_identity: x25519.Identity
    ed25519_sk: nacl.signing.SigningKey

    @property
    def age_recipient(self) -> str:
        return str(self.age_identity.to_public())

    @property
    def ed25519_pub(self) -> bytes:
        return bytes(self.ed25519_sk.verify_key)


def create_keyblob(passphrase: str) -> tuple[Keyblob, bytes]:
    """Génère un nouveau keyblob et renvoie (secret en clair, blob chiffré)."""
    identity = x25519.Identity.generate()
    ed = nacl.signing.SigningKey.generate()
    plain = {
        "v": KEYBLOB_VERSION,
        "age_identity": str(identity),
        "ed25519_sk": bytes(ed).hex(),
    }
    wrapped = age_passphrase.encrypt(json.dumps(plain).encode(), passphrase)
    return Keyblob(identity, ed), wrapped


def unlock_keyblob(passphrase: str, wrapped_seed: bytes) -> Keyblob:
    """SPEC §9 : *seul* point à remplacer par la carte à puce."""
    plain = json.loads(age_passphrase.decrypt(wrapped_seed, passphrase))
    if plain.get("v") != KEYBLOB_VERSION:
        raise ValueError(f"version de keyblob inconnue: {plain.get('v')!r}")
    identity = x25519.Identity.from_str(plain["age_identity"])
    ed = nacl.signing.SigningKey(bytes.fromhex(plain["ed25519_sk"]))
    return Keyblob(identity, ed)


# --------------------------------------------------------------------------- #
# Niveau GK (SPEC §6) — enveloppe age multi-destinataires, contenu = 32 octets
# bruts de la GK. Une enveloppe par époque, jamais une par membre.
# --------------------------------------------------------------------------- #
def new_gk() -> bytes:
    return nacl.utils.random(GK_LEN)


def seal_epoch(gk: bytes, recipients: list[str]) -> bytes:
    """Chiffre la GK vers l'ensemble des destinataires age (binaire, pas armor)."""
    if len(gk) != GK_LEN:
        raise ValueError("GK doit faire 32 octets")
    recips = [x25519.Recipient.from_str(r) for r in recipients]
    return age_encrypt(gk, recips)


def open_epoch(age_identity: x25519.Identity, envelope: bytes) -> bytes:
    """→ GK. Échoue si l'identité n'est pas destinataire de l'enveloppe."""
    gk = age_decrypt(envelope, [age_identity])
    if len(gk) != GK_LEN:
        raise ValueError("enveloppe d'époque corrompue")
    return gk


# --------------------------------------------------------------------------- #
# Niveau CEK / notes (SPEC §6) — XChaCha20-Poly1305, nonce aléatoire 24 octets.
# L'AAD lie chaque blob à sa ligne : il empêche le déplacement d'un payload.
# --------------------------------------------------------------------------- #
def _aad_note(note_id: uuid.UUID) -> bytes:
    return note_id.bytes


def _aad_payload(note_id: uuid.UUID, group_id: uuid.UUID, epoch_n: int) -> bytes:
    return note_id.bytes + group_id.bytes + struct.pack(">i", epoch_n)


def _aead_seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = nacl.utils.random(NONCE_LEN)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key
    )
    return nonce + ct


def _aead_open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)


def seal_note(
    gk: bytes,
    note_id: uuid.UUID,
    group_id: uuid.UUID,
    epoch_n: int,
    content: dict,
) -> tuple[bytes, bytes]:
    """→ (wrapped_cek, payload). CEK aléatoire, wrappée sous la GK courante."""
    cek = nacl.utils.random(CEK_LEN)
    wrapped_cek = _aead_seal(gk, cek, _aad_note(note_id))
    payload = _aead_seal(
        cek, json.dumps(content).encode(), _aad_payload(note_id, group_id, epoch_n)
    )
    return wrapped_cek, payload


def open_note(
    gk: bytes,
    note_id: uuid.UUID,
    group_id: uuid.UUID,
    epoch_n: int,
    wrapped_cek: bytes,
    payload: bytes,
) -> dict:
    cek = _aead_open(gk, wrapped_cek, _aad_note(note_id))
    plain = _aead_open(cek, payload, _aad_payload(note_id, group_id, epoch_n))
    return json.loads(plain)


# --------------------------------------------------------------------------- #
# Chaîne d'octrois (SPEC §7) — on signe et on stocke les MÊMES octets.
# --------------------------------------------------------------------------- #
def build_stmt(
    *,
    group_id: uuid.UUID,
    action: str,
    epoch: int,
    subject: str,
    key_id: Optional[uuid.UUID],
    gk_envelope: bytes,
    prev_hash: Optional[bytes],
    ts: int,
) -> bytes:
    """Encode une déclaration en CBOR. Ces octets exacts sont signés et stockés,
    jamais réencodés (SPEC §7, §13)."""
    if action not in ("found", "add", "remove"):
        raise ValueError(f"action inconnue: {action!r}")
    stmt = {
        "v": STMT_VERSION,
        "group": group_id.bytes,
        "action": action,
        "epoch": epoch,
        "subject": subject,
        "key_id": key_id.bytes if key_id is not None else None,
        "env": blake2b256(gk_envelope),
        "prev": prev_hash,
        "ts": ts,
    }
    return cbor2.dumps(stmt)


def sign_stmt(kb: Keyblob, stmt: bytes) -> bytes:
    return kb.ed25519_sk.sign(stmt).signature


@dataclass
class ChainEntry:
    """Une ligne de grant_stmt telle que rangée côté serveur."""

    seq: int
    stmt: bytes
    sig: bytes
    signer_ed25519_pub: bytes  # résolu via signer_key_id → member_key
    signer_matricule: str


class ChainError(Exception):
    pass


def replay_chain(
    entries: list[ChainEntry],
    envelope_for_epoch: dict[int, bytes],
    check_policy=None,
) -> set[str]:
    """Rejeu depuis seq=0 (SPEC §7). Renvoie l'ensemble des matricules membres.

    C'est *l'autorité* : le client ne fait jamais confiance à la vue serveur.
    ``check_policy(action, signer_matricule, members)`` est le crochet du lot 3
    (quorum) ; par défaut, le signataire doit être membre courant.
    """
    if check_policy is None:
        def check_policy(action, signer, members):
            if signer not in members:
                raise ChainError(
                    f"signataire non membre: {signer!r} (action {action})"
                )

    ordered = sorted(entries, key=lambda x: x.seq)

    # L'enveloppe d'une époque est réécrite en place à chaque cooption (SPEC §5).
    # Seule la *dernière* déclaration qui vise une époque pinne l'enveloppe
    # actuellement stockée ; les précédentes visaient une enveloppe désormais
    # écrasée — leur intégrité reste couverte par la signature et le chaînage.
    latest_seq_for_epoch: dict[int, int] = {}
    for e in ordered:
        ep = cbor2.loads(e.stmt)["epoch"]
        latest_seq_for_epoch[ep] = max(latest_seq_for_epoch.get(ep, -1), e.seq)

    members: set[str] = set()
    prev_hash: Optional[bytes] = None

    for e in ordered:
        stmt = cbor2.loads(e.stmt)

        # 1. chaînage
        if stmt["prev"] != prev_hash:
            raise ChainError(
                f"seq {e.seq}: prev rompu "
                f"(attendu {prev_hash!r}, lu {stmt['prev']!r})"
            )

        # 2. signature — structurelle, sur les octets exacts
        try:
            vk = nacl.signing.VerifyKey(e.signer_ed25519_pub)
            vk.verify(e.stmt, e.sig)
        except Exception as exc:
            raise ChainError(f"seq {e.seq}: signature invalide ({exc})")

        # 3. politique : au-delà de la fondation, le signataire doit être membre
        action = stmt["action"]
        if e.seq > 0:
            check_policy(action, e.signer_matricule, members)

        # 4. l'enveloppe stockée est bien celle qu'une déclaration a autorisée
        epoch = stmt["epoch"]
        env = envelope_for_epoch.get(epoch)
        if env is None:
            raise ChainError(f"seq {e.seq}: aucune enveloppe pour l'époque {epoch}")
        if e.seq == latest_seq_for_epoch[epoch] and stmt["env"] != blake2b256(env):
            raise ChainError(f"seq {e.seq}: env ne correspond pas à l'enveloppe stockée")

        # 5. application
        subject = stmt["subject"]
        if action in ("found", "add"):
            members.add(subject)
        elif action == "remove":
            members.discard(subject)

        prev_hash = blake2b256(e.stmt)

    return members
