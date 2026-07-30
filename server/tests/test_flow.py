"""Portage du scénario du lot 0 par-dessus l'API HTTP (SPEC §10), plus les
propriétés serveur : opacité des blobs, auth exigée, rejet structurel (§7).

Le client crypto est `lot0.model` : on prouve le contrat ET la compatibilité de
format Python↔serveur (le même code est l'outil de secours du test §11.7).
"""

from __future__ import annotations

import base64
import time
import uuid

from lot0 import model


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def d64(s: str) -> bytes:
    return base64.b64decode(s)


def enroll(client, matricule, name, passphrase):
    kb, wrapped = model.create_keyblob(passphrase)
    r = client.post(
        "/members",
        json={
            "matricule": matricule,
            "display_name": name,
            "age_recipient": kb.age_recipient,
            "ed25519_pub": b64(kb.ed25519_pub),
            "wrapped_seed": b64(wrapped),
        },
    )
    assert r.status_code == 201, r.text
    return kb, r.json()  # {member_id, key_id}


def login(client, matricule, kb):
    nonce = d64(client.post("/auth/challenge", json={"matricule": matricule}).json()["nonce"])
    sig = kb.ed25519_sk.sign(nonce).signature
    r = client.post("/auth/verify", json={"matricule": matricule, "sig": b64(sig)})
    assert r.status_code == 204, r.text


def test_full_flow(client):
    # --- enrôlement + session (défi-réponse Ed25519) ---
    kb, ids = enroll(client, "MAT-A", "Alice", "pass-alice")
    key_id = uuid.UUID(ids["key_id"])
    login(client, "MAT-A", kb)

    # keyblob récupérable (chiffré, donc public)
    blob = d64(client.get("/me/keyblob").json()["wrapped_seed"])
    assert model.unlock_keyblob("pass-alice", blob).age_recipient == kb.age_recipient

    # --- genèse du groupe : groupe + époque 0 + déclaration `found` ---
    gid = uuid.uuid4()
    assert client.post("/groups", json={"id": str(gid), "name": "notes"}).status_code == 201

    gk = model.new_gk()
    env = model.seal_epoch(gk, [kb.age_recipient])
    found = model.build_stmt(
        group_id=gid, action="found", epoch=0, subject="MAT-A", key_id=key_id,
        gk_envelope=env, prev_hash=None, ts=int(time.time()),
    )
    sig = model.sign_stmt(kb, found)
    r = client.post(
        f"/groups/{gid}/epochs",
        json={"n": 0, "gk_envelope": b64(env), "seq": 0, "stmt": b64(found),
              "sig": b64(sig), "signer_key_id": str(key_id)},
    )
    assert r.status_code == 201, r.text

    # --- écriture d'une note (scellée côté client) ---
    nid = uuid.uuid4()
    wrapped_cek, payload = model.seal_note(gk, nid, gid, 0, {"title": "T", "body": "secret-http"})
    r = client.post(
        "/notes",
        json={"id": str(nid), "group_id": str(gid), "epoch_n": 0,
              "wrapped_cek": b64(wrapped_cek), "payload": b64(payload)},
    )
    assert r.status_code == 201, r.text

    # --- lecture : le serveur ne renvoie que des blobs, le client déchiffre ---
    notes = client.get(f"/notes?group_id={gid}").json()
    assert len(notes) == 1
    row = notes[0]
    content = model.open_note(
        gk, uuid.UUID(row["id"]), gid, row["epoch_n"], d64(row["wrapped_cek"]), d64(row["payload"])
    )
    assert content == {"title": "T", "body": "secret-http"}

    # --- rejeu de la chaîne côté client (l'autorité) ---
    grants = client.get(f"/groups/{gid}/grants").json()
    entries = [
        model.ChainEntry(
            seq=g["seq"], stmt=d64(g["stmt"]), sig=d64(g["sig"]),
            signer_ed25519_pub=d64(g["signer_ed25519_pub"]),
            signer_matricule=g["signer_matricule"],
        )
        for g in grants
    ]
    epochs = {e["n"]: d64(e["gk_envelope"]) for e in client.get(f"/groups/{gid}/epochs").json()}
    assert model.replay_chain(entries, epochs) == {"MAT-A"}


def test_requires_auth(client):
    assert client.get("/me/keyblob").status_code == 401
    assert client.get(f"/notes?group_id={uuid.uuid4()}").status_code == 401


def test_server_rejects_malformed_grant(client):
    """§7 confort : une signature invalide est refusée par le serveur (400).
    (L'autorité de politique, elle, est prouvée côté client au test §11.4.)"""
    kb, ids = enroll(client, "MAT-A", "Alice", "pw")
    key_id = uuid.UUID(ids["key_id"])
    login(client, "MAT-A", kb)
    gid = uuid.uuid4()
    client.post("/groups", json={"id": str(gid), "name": "g"})

    gk = model.new_gk()
    env = model.seal_epoch(gk, [kb.age_recipient])
    found = model.build_stmt(
        group_id=gid, action="found", epoch=0, subject="MAT-A", key_id=key_id,
        gk_envelope=env, prev_hash=None, ts=0,
    )
    bad_sig = bytes(64)  # signature nulle → invalide
    r = client.post(
        f"/groups/{gid}/epochs",
        json={"n": 0, "gk_envelope": b64(env), "seq": 0, "stmt": b64(found),
              "sig": b64(bad_sig), "signer_key_id": str(key_id)},
    )
    assert r.status_code == 400, r.text
