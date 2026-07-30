from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from ..auth import CurrentMember, SessionMember
from ..codec import b64d, b64e
from ..db import pool
from ..schemas import NoteCreateReq, NotePatchReq, NoteResp, NoteResp201

router = APIRouter(prefix="/notes", tags=["notes"])


def _row_to_note(r) -> NoteResp:
    return NoteResp(
        id=r["id"],
        group_id=r["group_id"],
        epoch_n=r["epoch_n"],
        author_id=r["author_id"],
        wrapped_cek=b64e(r["wrapped_cek"]),
        payload=b64e(r["payload"]),
        created_at=r["created_at"].isoformat(),
        updated_at=r["updated_at"].isoformat(),
    )


@router.get("", response_model=list[NoteResp])
def list_notes(group_id: uuid.UUID = Query(...), me: SessionMember = CurrentMember):
    """Métadonnées + blobs (SPEC §8). `payload` et `wrapped_cek` sont opaques :
    le serveur ne peut pas les lire."""
    with pool().connection() as conn:
        rows = conn.execute(
            "SELECT * FROM note WHERE group_id = %s ORDER BY created_at DESC", (group_id,)
        ).fetchall()
    return [_row_to_note(r) for r in rows]


@router.post("", response_model=NoteResp201, status_code=201)
def create_note(req: NoteCreateReq, me: SessionMember = CurrentMember):
    with pool().connection() as conn:
        epoch = conn.execute(
            "SELECT 1 FROM epoch WHERE group_id = %s AND n = %s", (req.group_id, req.epoch_n)
        ).fetchone()
        if epoch is None:
            raise HTTPException(status_code=400, detail="époque inexistante pour ce groupe")
        dup = conn.execute("SELECT 1 FROM note WHERE id = %s", (req.id,)).fetchone()
        if dup:
            raise HTTPException(status_code=409, detail="note déjà existante")
        row = conn.execute(
            "INSERT INTO note (id, group_id, epoch_n, author_id, wrapped_cek, payload) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
            (
                req.id,
                req.group_id,
                req.epoch_n,
                me.member_id,
                b64d(req.wrapped_cek),
                b64d(req.payload),
            ),
        ).fetchone()
    return NoteResp201(id=row["id"])


@router.patch("/{note_id}", status_code=204)
def update_note(note_id: uuid.UUID, req: NotePatchReq, me: SessionMember = CurrentMember):
    with pool().connection() as conn:
        n = conn.execute(
            "UPDATE note SET wrapped_cek = %s, payload = %s, epoch_n = %s, updated_at = now() "
            "WHERE id = %s",
            (b64d(req.wrapped_cek), b64d(req.payload), req.epoch_n, note_id),
        )
        if n.rowcount == 0:
            raise HTTPException(status_code=404, detail="note inconnue")
