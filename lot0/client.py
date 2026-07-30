"""Lot 0 — le client membre.

Détient un keyblob déverrouillé en mémoire et orchestre les flux de la SPEC
§10 en parlant au store. C'est ici que vit l'autorité : chaque action de
lecture de composition passe par ``replay_chain`` (model.py), jamais par la vue
serveur.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from . import model
from .model import Keyblob
from .store import Store


@dataclass
class Member:
    matricule: str
    member_id: uuid.UUID
    key_id: uuid.UUID
    kb: Keyblob


def enroll(store: Store, matricule: str, display_name: str, passphrase: str) -> Member:
    """SPEC §10 enrôlement : le client génère tout, le serveur ne reçoit que du public."""
    kb, wrapped = model.create_keyblob(passphrase)
    mid = store.add_member(matricule, display_name)
    kid = store.add_key(mid, kb.age_recipient, kb.ed25519_pub, wrapped)
    return Member(matricule, mid, kid, kb)


def login(store: Store, matricule: str, passphrase: str) -> Member:
    """Ouverture de session : GET /me/keyblob puis déverrouillage local."""
    wrapped = store.keyblob(matricule)
    kb = model.unlock_keyblob(passphrase, wrapped)
    m = store.member_by_matricule(matricule)
    key = store.db.execute(
        "SELECT id FROM member_key WHERE member_id = ? AND active = 1",
        (str(m["id"]),),
    ).fetchone()
    return Member(matricule, uuid.UUID(m["id"]), uuid.UUID(key["id"]), kb)


def _recipients(store: Store, matricules: list[str]) -> list[str]:
    out = []
    for mat in matricules:
        m = store.member_by_matricule(mat)
        row = store.db.execute(
            "SELECT age_recipient FROM member_key WHERE member_id = ? AND active = 1",
            (str(m["id"]),),
        ).fetchone()
        out.append(row["age_recipient"])
    return out


def found_group(store: Store, founder: Member, name: str) -> uuid.UUID:
    """Genèse : GK neuve, enveloppe d'époque 0 vers le fondateur, déclaration `found`."""
    gid = store.create_group(name)
    gk = model.new_gk()
    env = model.seal_epoch(gk, _recipients(store, [founder.matricule]))
    store.put_epoch(gid, 0, env)

    stmt = model.build_stmt(
        group_id=gid,
        action="found",
        epoch=0,
        subject=founder.matricule,
        key_id=founder.key_id,
        gk_envelope=env,
        prev_hash=None,
        ts=int(time.time()),
    )
    sig = model.sign_stmt(founder.kb, stmt)
    store.append_grant(gid, 0, stmt, sig, founder.key_id, model.blake2b256(stmt))
    return gid


def open_gks(store: Store, m: Member, group_id: uuid.UUID) -> dict[int, bytes]:
    """Ouvre toutes les enveloppes d'époque déchiffrables par ce membre → GK en mémoire."""
    gks: dict[int, bytes] = {}
    for n, env in store.epochs(group_id).items():
        try:
            gks[n] = model.open_epoch(m.kb.age_identity, env)
        except Exception:
            pass  # époque à laquelle ce membre n'a pas accès — normal
    return gks


def write_note(
    store: Store, m: Member, group_id: uuid.UUID, gks: dict[int, bytes], content: dict
) -> uuid.UUID:
    """Écriture : CEK aléatoire, wrap sous la GK de l'époque *courante*."""
    epoch_n = store.current_epoch(group_id)
    if epoch_n not in gks:
        raise PermissionError("pas de GK pour l'époque courante — écriture impossible")
    nid = uuid.uuid4()
    wrapped_cek, payload = model.seal_note(
        gks[epoch_n], nid, group_id, epoch_n, content
    )
    store.put_note(nid, group_id, epoch_n, m.member_id, wrapped_cek, payload)
    return nid


def read_notes(
    store: Store, group_id: uuid.UUID, gks: dict[int, bytes]
) -> list[dict]:
    """Lecture : déwrap CEK sous la GK de l'époque de chaque note, puis déchiffrement."""
    out = []
    for row in store.notes(group_id):
        n = row["epoch_n"]
        if n not in gks:
            out.append({"id": row["id"], "epoch_n": n, "readable": False})
            continue
        content = model.open_note(
            gks[n],
            uuid.UUID(row["id"]),
            group_id,
            n,
            row["wrapped_cek"],
            row["payload"],
        )
        out.append({"id": row["id"], "epoch_n": n, "readable": True, **content})
    return out


def coopt(
    store: Store,
    coopter: Member,
    group_id: uuid.UUID,
    gks: dict[int, bytes],
    newcomer: str,
    rewrap_history: bool = False,
):
    """Cooptation (SPEC §10) : réencode l'enveloppe courante vers +1 destinataire,
    signe une déclaration `add`. Les notes ne sont pas touchées.

    ``rewrap_history=True`` rewrappe aussi les époques antérieures → accès au
    passé (choix explicite, cf. test §11.6)."""
    members = current_members(store, group_id)
    targets = sorted(members | {newcomer})
    cur = store.current_epoch(group_id)
    newcomer_key = _active_key_id(store, newcomer)

    # Chaque époque rewrappée est re-pinnée par une déclaration `add` qui la vise :
    # ainsi la dernière déclaration de chaque époque correspond bien à l'enveloppe
    # stockée (cf. rejeu, model.replay_chain). En rewrap courant seul, une seule.
    epochs_to_rewrap = sorted(store.epochs(group_id)) if rewrap_history else [cur]
    for n in epochs_to_rewrap:
        if n not in gks:
            raise PermissionError(f"coopteur sans GK pour l'époque {n}")
        env = model.seal_epoch(gks[n], _recipients(store, targets))
        store.db.execute(
            "UPDATE epoch SET gk_envelope = ? WHERE group_id = ? AND n = ?",
            (env, str(group_id), n),
        )
        store.db.commit()
        _append(store, coopter, group_id, "add", n, newcomer, newcomer_key, env)


def remove_member(
    store: Store,
    remover: Member,
    group_id: uuid.UUID,
    gks: dict[int, bytes],
    departing: str,
):
    """Radiation (SPEC §10) : GK neuve, nouvelle époque vers les restants,
    déclaration `remove`. Les époques antérieures restent lisibles par le partant."""
    members = current_members(store, group_id)
    remaining = sorted(members - {departing})
    new_n = store.current_epoch(group_id) + 1

    gk = model.new_gk()
    env = model.seal_epoch(gk, _recipients(store, remaining))
    store.put_epoch(group_id, new_n, env)
    gks[new_n] = gk  # le remover garde sa GK en mémoire

    _append(store, remover, group_id, "remove", new_n, departing, None, env)


# --------------------------------------------------------------------------- #
# Autorité : composition reconstruite depuis la chaîne, jamais depuis une table.
# --------------------------------------------------------------------------- #
def current_members(store: Store, group_id: uuid.UUID, check_policy=None) -> set[str]:
    entries = [
        model.ChainEntry(
            seq=r["seq"],
            stmt=r["stmt"],
            sig=r["sig"],
            signer_ed25519_pub=r["signer_pub"],
            signer_matricule=r["signer_matricule"],
        )
        for r in store.grants(group_id)
    ]
    return model.replay_chain(entries, store.epochs(group_id), check_policy)


def _active_key_id(store: Store, matricule: str) -> uuid.UUID:
    m = store.member_by_matricule(matricule)
    row = store.db.execute(
        "SELECT id FROM member_key WHERE member_id = ? AND active = 1",
        (str(m["id"]),),
    ).fetchone()
    return uuid.UUID(row["id"])


def _append(store, signer: Member, group_id, action, epoch, subject, key_id, env):
    seq = store.next_seq(group_id)
    prev = store.grants(group_id)
    prev_hash = prev[-1]["hash"] if prev else None
    stmt = model.build_stmt(
        group_id=group_id,
        action=action,
        epoch=epoch,
        subject=subject,
        key_id=key_id,
        gk_envelope=env,
        prev_hash=prev_hash,
        ts=int(time.time()),
    )
    sig = model.sign_stmt(signer.kb, stmt)
    store.append_grant(group_id, seq, stmt, sig, signer.key_id, model.blake2b256(stmt))
