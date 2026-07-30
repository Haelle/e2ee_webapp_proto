"""Lot 0 — scénario complet et vérifications de la SPEC §11.

    python -m lot0.demo

Rejoue genèse → écriture → cooptation → radiation → nouvelle époque → rejeu de
chaîne, puis exécute chaque vérification §11 comme une assertion (pas comme une
intention). Sort avec un code non nul si l'une échoue.
"""

from __future__ import annotations

import os
import sys
import tempfile
import uuid

import nacl.exceptions

from . import client, model
from .model import ChainError
from .store import Store

MARKERS = [
    "secret-alpha", "secret-beta", "secret-gamma",
    "titre-canari-1", "titre-canari-2", "titre-canari-3",
]


def build_scenario(store: Store) -> dict:
    """Le flux honnête, de bout en bout. Renvoie les poignées pour les assertions."""
    alice = client.enroll(store, "MAT-A", "Alice", "pass-alice")
    bob = client.enroll(store, "MAT-B", "Bob", "pass-bob")
    carol = client.enroll(store, "MAT-C", "Carol", "pass-carol")
    dave = client.enroll(store, "MAT-D", "Dave", "pass-dave")
    eve = client.enroll(store, "MAT-E", "Eve (jamais membre)", "pass-eve")

    gid = client.found_group(store, alice, "notes")
    gk_a = client.open_gks(store, alice, gid)

    # Alice coopte Bob à l'époque 0 (une seule époque : rewrap de la courante)
    client.coopt(store, alice, gid, gk_a, "MAT-B")
    gk_a = client.open_gks(store, alice, gid)
    gk_b = client.open_gks(store, bob, gid)

    n1 = client.write_note(store, alice, gid, gk_a, {"title": "titre-canari-1", "body": "secret-alpha"})
    n2 = client.write_note(store, bob, gid, gk_b, {"title": "titre-canari-2", "body": "secret-beta"})

    # Alice radie Bob → époque 1, GK neuve vers {Alice} uniquement
    client.remove_member(store, alice, gid, gk_a, "MAT-B")
    gk_a = client.open_gks(store, alice, gid)
    n3 = client.write_note(store, alice, gid, gk_a, {"title": "titre-canari-3", "body": "secret-gamma"})

    return dict(
        alice=alice, bob=bob, carol=carol, dave=dave, eve=eve,
        gid=gid, gk_a=gk_a, n1=n1, n2=n2, n3=n3,
    )


# --------------------------------------------------------------------------- #
CHECKS = []


def check(name):
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


@check("§11.1  aucun contenu clair dans un dump de la base")
def c1():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "db.sqlite")
        s = Store(path)
        build_scenario(s)
        s.db.commit()
        s.close()
        raw = open(path, "rb").read()
    for marker in MARKERS:
        assert marker.encode() not in raw, f"marqueur {marker!r} lisible dans le dump"


@check("§11.2  un membre d'une époque ne peut pas ouvrir l'enveloppe suivante")
def c2():
    s = Store()
    sc = build_scenario(s)
    # Bob n'est destinataire que de l'époque 0 ; l'époque 1 lui est fermée
    env1 = s.epochs(sc["gid"])[1]
    try:
        model.open_epoch(sc["bob"].kb.age_identity, env1)
    except Exception:
        s.close()
        return
    s.close()
    raise AssertionError("Bob a pu ouvrir l'enveloppe de l'époque suivante")


@check("§11.3  échanger deux payload en SQL direct casse le déchiffrement (AAD)")
def c3():
    s = Store()
    sc = build_scenario(s)
    gid = sc["gid"]
    rows = s.notes(gid)
    a, b = rows[0], rows[1]
    # échange brut des payload entre deux lignes
    s.db.execute("UPDATE note SET payload = ? WHERE id = ?", (b["payload"], a["id"]))
    s.db.execute("UPDATE note SET payload = ? WHERE id = ?", (a["payload"], b["id"]))
    s.db.commit()
    gks = client.open_gks(s, sc["alice"], gid)
    row = s.db.execute("SELECT * FROM note WHERE id = ?", (a["id"],)).fetchone()
    try:
        model.open_note(
            gks[row["epoch_n"]], uuid.UUID(row["id"]), gid, row["epoch_n"],
            row["wrapped_cek"], row["payload"],
        )
    except nacl.exceptions.CryptoError:
        s.close()
        return
    s.close()
    raise AssertionError("un payload déplacé s'est déchiffré (AAD absente ?)")


@check("§11.4  déclaration d'un non-membre : acceptée par le serveur, rejetée au rejeu")
def c4():
    s = Store()
    sc = build_scenario(s)
    gid = sc["gid"]
    eve = sc["eve"]  # enrôlée, jamais ajoutée au groupe
    # le « serveur » range la déclaration sans vérifier la politique
    seq = s.next_seq(gid)
    prev = s.grants(gid)[-1]["hash"]
    env = s.epochs(gid)[s.current_epoch(gid)]
    stmt = model.build_stmt(
        group_id=gid, action="add", epoch=s.current_epoch(gid),
        subject="MAT-C", key_id=client._active_key_id(s, "MAT-C"),
        gk_envelope=env, prev_hash=prev, ts=0,
    )
    sig = model.sign_stmt(eve.kb, stmt)
    s.append_grant(gid, seq, stmt, sig, eve.key_id, model.blake2b256(stmt))
    # le client, lui, revérifie tout et rejette
    try:
        client.current_members(s, gid)
    except ChainError:
        s.close()
        return
    s.close()
    raise AssertionError("le rejeu client a accepté une déclaration de non-membre")


@check("§11.5  modifier un stmt en base casse la chaîne au prev suivant")
def c5():
    s = Store()
    sc = build_scenario(s)
    gid = sc["gid"]
    row0 = s.grants(gid)[0]
    tampered = bytearray(row0["stmt"])
    tampered[-1] ^= 0x01  # un octet retourné
    s.db.execute(
        "UPDATE grant_stmt SET stmt = ? WHERE group_id = ? AND seq = 0",
        (bytes(tampered), str(gid)),
    )
    s.db.commit()
    try:
        client.current_members(s, gid)
    except ChainError:
        s.close()
        return
    s.close()
    raise AssertionError("la chaîne n'a pas cassé après modification d'un stmt")


@check("§11.6  historique lisible ssi les anciennes enveloppes ont été rewrappées")
def c6():
    s = Store()
    sc = build_scenario(s)
    gid = sc["gid"]

    # Carol cooptée à l'époque 1 SANS rewrap de l'historique
    client.coopt(s, sc["alice"], gid, sc["gk_a"], "MAT-C", rewrap_history=False)
    carol_gks = client.open_gks(s, sc["carol"], gid)
    carol = client.read_notes(s, gid, carol_gks)
    hist = [n for n in carol if n["epoch_n"] == 0]
    assert all(not n["readable"] for n in hist), "Carol a lu l'historique sans rewrap"
    cur = [n for n in carol if n["epoch_n"] == 1]
    assert all(n["readable"] for n in cur), "Carol ne lit pas l'époque courante"

    # Dave coopté AVEC rewrap de l'historique
    client.coopt(s, sc["alice"], gid, sc["gk_a"], "MAT-D", rewrap_history=True)
    dave_gks = client.open_gks(s, sc["dave"], gid)
    dave = client.read_notes(s, gid, dave_gks)
    assert all(n["readable"] for n in dave), "Dave ne lit pas l'historique après rewrap"
    s.close()


@check("§11.7  l'outil hors ligne déchiffre un dump sans le serveur")
def c7():
    from . import recover
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "db.sqlite")
        s = Store(path)
        build_scenario(s)
        s.db.commit()
        s.close()
        # aucune instance de client conservée : on repart du seul fichier
        members, gks, notes = recover.recover(path, "MAT-A", "pass-alice", "notes")
    assert members == {"MAT-A"}, f"composition inattendue: {members}"
    readable = [n for n in notes if n["readable"]]
    bodies = {n["body"] for n in readable}
    assert "secret-gamma" in bodies, "note d'époque courante non récupérée"


def main() -> int:
    failed = 0
    for name, fn in CHECKS:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {name}\n        → {e}")
        except Exception as e:
            failed += 1
            print(f"  ERR   {name}\n        → {type(e).__name__}: {e}")
    print()
    if failed:
        print(f"{failed}/{len(CHECKS)} vérification(s) en échec.")
        return 1
    print(f"Les {len(CHECKS)} vérifications de la SPEC §11 passent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
