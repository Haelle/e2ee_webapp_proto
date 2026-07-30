from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..auth import CurrentMember, SessionMember
from ..codec import b64d, b64e
from ..db import pool
from ..schemas import EnrollReq, EnrollResp, KeyblobResp, RotateReq

router = APIRouter(tags=["members"])


@router.post("/members", response_model=EnrollResp, status_code=201)
def enroll(req: EnrollReq):
    """Enrôlement (SPEC §10) : le serveur ne reçoit que du public + un keyblob
    chiffré. Rien d'exploitable."""
    with pool().connection() as conn:
        exists = conn.execute(
            "SELECT 1 FROM member WHERE matricule = %s", (req.matricule,)
        ).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="matricule déjà enrôlé")
        member = conn.execute(
            "INSERT INTO member (matricule, display_name) VALUES (%s, %s) RETURNING id",
            (req.matricule, req.display_name),
        ).fetchone()
        key = conn.execute(
            "INSERT INTO member_key (member_id, age_recipient, ed25519_pub, wrapped_seed) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (member["id"], req.age_recipient, b64d(req.ed25519_pub), b64d(req.wrapped_seed)),
        ).fetchone()
    return EnrollResp(member_id=member["id"], key_id=key["id"])


@router.get("/me/keyblob", response_model=KeyblobResp)
def keyblob(me: SessionMember = CurrentMember):
    """Le keyblob chiffré, donc public (SPEC §8). Sert au déverrouillage local."""
    with pool().connection() as conn:
        row = conn.execute(
            "SELECT wrapped_seed FROM member_key WHERE member_id = %s AND active",
            (me.member_id,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="aucune clé active")
    return KeyblobResp(wrapped_seed=b64e(row["wrapped_seed"]))


@router.post("/members/me/keys", status_code=201)
def rotate(req: RotateReq, me: SessionMember = CurrentMember):
    """Rotation de clé personnelle (SPEC §10) : nouveau member_key, l'ancien
    passe inactif. Le rewrap des enveloppes d'époque est une étape client
    séparée (lot 3)."""
    with pool().connection() as conn:
        conn.execute(
            "UPDATE member_key SET active = false WHERE member_id = %s AND active",
            (me.member_id,),
        )
        key = conn.execute(
            "INSERT INTO member_key (member_id, age_recipient, ed25519_pub, wrapped_seed) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (me.member_id, req.age_recipient, b64d(req.ed25519_pub), b64d(req.wrapped_seed)),
        ).fetchone()
    return {"key_id": str(key["id"])}
