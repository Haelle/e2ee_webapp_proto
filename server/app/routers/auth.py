from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

from .. import auth
from ..codec import b64d, b64e
from ..db import pool
from ..schemas import ChallengeReq, ChallengeResp, VerifyReq

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/challenge", response_model=ChallengeResp)
def challenge(req: ChallengeReq):
    # On émet un nonce même si le matricule est inconnu (pas d'oracle d'existence).
    nonce = auth.new_challenge(req.matricule)
    return ChallengeResp(nonce=b64e(nonce))


@router.post("/verify", status_code=204)
def verify(req: VerifyReq, request: Request, response: Response):
    nonce = auth.consume_challenge(req.matricule)
    if nonce is None:
        raise HTTPException(status_code=400, detail="défi absent ou expiré")

    with pool().connection() as conn:
        row = conn.execute(
            "SELECT m.id AS member_id, mk.id AS key_id, mk.ed25519_pub "
            "FROM member m JOIN member_key mk ON mk.member_id = m.id "
            "WHERE m.matricule = %s AND mk.active",
            (req.matricule,),
        ).fetchone()

    if row is None or not auth.verify_response(bytes(row["ed25519_pub"]), nonce, b64d(req.sig)):
        raise HTTPException(status_code=401, detail="réponse au défi invalide")

    request.session.update(
        member_id=str(row["member_id"]),
        matricule=req.matricule,
        key_id=str(row["key_id"]),
    )
    return Response(status_code=204)


@router.post("/logout", status_code=204)
def logout(request: Request):
    request.session.clear()
    return Response(status_code=204)
