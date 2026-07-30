"""Lot 0 — outil de secours hors ligne (SPEC §11 test 7, §2 clé de recours).

Déchiffre un dump de la base *sans le serveur* : on n'a besoin que du keyblob
chiffré (stocké dans la base, donc récupérable depuis le dump lui-même) et de la
passphrase. Prouve que l'autorité et la lisibilité ne dépendent que du client.

    python -m lot0.recover <db.sqlite> <matricule> <passphrase> <group_name>
"""

from __future__ import annotations

import sys
import uuid

from . import client, model
from .store import Store


def recover(db_path: str, matricule: str, passphrase: str, group_name: str):
    store = Store(db_path)

    # 1. récupérer le keyblob chiffré et le déverrouiller — aucune logique serveur
    wrapped = store.keyblob(matricule)
    kb = model.unlock_keyblob(passphrase, wrapped)

    row = store.db.execute("SELECT id FROM grp WHERE name = ?", (group_name,)).fetchone()
    if row is None:
        raise SystemExit(f"groupe introuvable: {group_name!r}")
    gid = uuid.UUID(row["id"])

    m = client.login(store, matricule, passphrase)

    # 2. autorité : composition reconstruite depuis la chaîne signée
    members = client.current_members(store, gid)

    # 3. lisibilité : ouvrir les GK accessibles puis les notes
    gks = client.open_gks(store, m, gid)
    notes = client.read_notes(store, gid, gks)

    store.close()
    return members, gks, notes


def _main(argv):
    if len(argv) != 4:
        print(__doc__)
        raise SystemExit(2)
    db_path, matricule, passphrase, group_name = argv
    members, gks, notes = recover(db_path, matricule, passphrase, group_name)
    print(f"# Récupération hors ligne — {matricule}")
    print(f"membres (rejeu de chaîne) : {sorted(members)}")
    print(f"époques ouvertes          : {sorted(gks)}")
    for n in notes:
        if n["readable"]:
            print(f"  [ép.{n['epoch_n']}] {n.get('title')!r} — {n.get('body')!r}")
        else:
            print(f"  [ép.{n['epoch_n']}] <illisible : pas de GK>")


if __name__ == "__main__":
    _main(sys.argv[1:])
