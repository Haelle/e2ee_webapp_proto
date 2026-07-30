from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from ..auth import CurrentMember, SessionMember
from ..chain import GrantRejected, hash_stmt, verify_structural
from ..codec import b64d, b64e
from ..db import pool
from ..schemas import (
    EpochCreateReq,
    EpochResp,
    GrantReq,
    GrantResp,
    GroupCreateReq,
    GroupResp,
)

router = APIRouter(prefix="/groups", tags=["groups"])


def _signer_pub(conn, signer_key_id: uuid.UUID) -> bytes:
    row = conn.execute(
        "SELECT ed25519_pub FROM member_key WHERE id = %s", (signer_key_id,)
    ).fetchone()
    if row is None:
        raise GrantRejected("signataire inconnu")
    return bytes(row["ed25519_pub"])


def _chain_head(conn, group_id: uuid.UUID) -> tuple[int, bytes | None]:
    row = conn.execute(
        "SELECT seq, hash FROM grant_stmt WHERE group_id = %s ORDER BY seq DESC LIMIT 1",
        (group_id,),
    ).fetchone()
    if row is None:
        return 0, None
    return row["seq"] + 1, bytes(row["hash"])


def _append_grant(conn, group_id: uuid.UUID, g: GrantReq | EpochCreateReq) -> bytes:
    """Vérifie la forme (SPEC §7 confort) puis stocke les octets EXACTS reçus."""
    stmt, sig = b64d(g.stmt), b64d(g.sig)
    expected_seq, prev_hash = _chain_head(conn, group_id)
    try:
        verify_structural(
            group_id=group_id,
            seq=g.seq,
            stmt=stmt,
            sig=sig,
            signer_ed25519_pub=_signer_pub(conn, g.signer_key_id),
            expected_seq=expected_seq,
            prev_hash=prev_hash,
        )
    except GrantRejected as exc:
        raise HTTPException(status_code=400, detail=f"déclaration rejetée: {exc}") from exc
    h = hash_stmt(stmt)
    conn.execute(
        "INSERT INTO grant_stmt (group_id, seq, stmt, sig, signer_key_id, hash) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (group_id, g.seq, stmt, sig, g.signer_key_id, h),
    )
    return h


# --- groupes --------------------------------------------------------------- #
@router.get("", response_model=list[GroupResp])
def list_groups(me: SessionMember = CurrentMember):
    """Vue serveur — INDICATIVE (SPEC §8, §13). L'autorité reste le rejeu de chaîne."""
    with pool().connection() as conn:
        rows = conn.execute("SELECT id, name FROM grp ORDER BY created_at").fetchall()
    return [GroupResp(**r) for r in rows]


@router.post("", response_model=GroupResp, status_code=201)
def create_group(req: GroupCreateReq, me: SessionMember = CurrentMember):
    """Genèse d'un groupe. Extension au-delà de §8 (qui n'a pas de POST /groups) :
    le client fournit l'UUID pour que la déclaration `found` puisse le référencer.
    Le premier POST /epochs y ajoutera l'époque 0 et la fondation."""
    with pool().connection() as conn:
        exists = conn.execute("SELECT 1 FROM grp WHERE id = %s OR name = %s", (req.id, req.name)).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="groupe déjà existant")
        conn.execute("INSERT INTO grp (id, name) VALUES (%s, %s)", (req.id, req.name))
    return GroupResp(id=req.id, name=req.name)


# --- époques --------------------------------------------------------------- #
@router.get("/{group_id}/epochs", response_model=list[EpochResp])
def list_epochs(group_id: uuid.UUID, me: SessionMember = CurrentMember):
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT n, gk_envelope FROM epoch WHERE group_id = %s ORDER BY n", (group_id,)
        ).fetchall()
    return [EpochResp(n=r["n"], gk_envelope=b64e(r["gk_envelope"])) for r in rows]


@router.post("/{group_id}/epochs", status_code=201)
def create_epoch(group_id: uuid.UUID, req: EpochCreateReq, me: SessionMember = CurrentMember):
    """Nouvelle époque : enveloppe + déclaration associée, dans une transaction
    (SPEC §8). L'enveloppe est stockée en binaire (pas d'armor ASCII, §13)."""
    with pool().connection() as conn:
        with conn.transaction():
            dup = conn.execute(
                "SELECT 1 FROM epoch WHERE group_id = %s AND n = %s", (group_id, req.n)
            ).fetchone()
            if dup:
                raise HTTPException(status_code=409, detail="époque déjà présente")
            # l'époque doit exister pour que la déclaration la référence (FK note),
            # mais la déclaration doit chaîner : on insère l'époque puis le grant.
            conn.execute(
                "INSERT INTO epoch (group_id, n, gk_envelope) VALUES (%s, %s, %s)",
                (group_id, req.n, b64d(req.gk_envelope)),
            )
            _append_grant(conn, group_id, req)
    return {"n": req.n}


# --- chaîne d'octrois ------------------------------------------------------ #
@router.get("/{group_id}/grants", response_model=list[GrantResp])
def list_grants(group_id: uuid.UUID, me: SessionMember = CurrentMember):
    """Chaîne complète, avec la clé publique du signataire résolue : le client en
    a besoin pour rejouer et tout revérifier lui-même (SPEC §7)."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT g.seq, g.stmt, g.sig, g.signer_key_id, g.hash, "
            "       mk.ed25519_pub AS signer_pub, m.matricule AS signer_matricule "
            "FROM grant_stmt g "
            "JOIN member_key mk ON mk.id = g.signer_key_id "
            "JOIN member m ON m.id = mk.member_id "
            "WHERE g.group_id = %s ORDER BY g.seq",
            (group_id,),
        ).fetchall()
    return [
        GrantResp(
            seq=r["seq"],
            stmt=b64e(r["stmt"]),
            sig=b64e(r["sig"]),
            signer_key_id=r["signer_key_id"],
            signer_ed25519_pub=b64e(r["signer_pub"]),
            signer_matricule=r["signer_matricule"],
            hash=b64e(r["hash"]),
        )
        for r in rows
    ]


@router.post("/{group_id}/grants", status_code=201)
def append_grant(group_id: uuid.UUID, req: GrantReq, me: SessionMember = CurrentMember):
    with pool().connection() as conn:
        with conn.transaction():
            _append_grant(conn, group_id, req)
    return {"seq": req.seq}
