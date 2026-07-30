"""Lot 0 — le « serveur », version SQLite.

Volontairement bête : il range des blobs et n'importe *aucune* fonction de
chiffrement (SPEC §4). Le schéma reproduit §5 (uuid→text, bytea→blob,
timestamptz→text ISO). Le contrôle d'accès serait ici, mais en local il n'y a
personne à qui mentir : le point prouvé est qu'un dump ne révèle rien.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS member (
  id           TEXT PRIMARY KEY,
  matricule    TEXT UNIQUE NOT NULL,
  display_name TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS member_key (
  id            TEXT PRIMARY KEY,
  member_id     TEXT NOT NULL REFERENCES member(id),
  age_recipient TEXT NOT NULL,
  ed25519_pub   BLOB NOT NULL,
  wrapped_seed  BLOB NOT NULL,
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS member_key_active
  ON member_key (member_id) WHERE active = 1;

CREATE TABLE IF NOT EXISTS grp (
  id         TEXT PRIMARY KEY,
  name       TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS epoch (
  group_id    TEXT NOT NULL REFERENCES grp(id),
  n           INTEGER NOT NULL,
  gk_envelope BLOB NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (group_id, n)
);

CREATE TABLE IF NOT EXISTS grant_stmt (
  group_id      TEXT NOT NULL REFERENCES grp(id),
  seq           INTEGER NOT NULL,
  stmt          BLOB NOT NULL,
  sig           BLOB NOT NULL,
  signer_key_id TEXT NOT NULL REFERENCES member_key(id),
  hash          BLOB NOT NULL,
  PRIMARY KEY (group_id, seq)
);

CREATE TABLE IF NOT EXISTS note (
  id          TEXT PRIMARY KEY,
  group_id    TEXT NOT NULL REFERENCES grp(id),
  epoch_n     INTEGER NOT NULL,
  author_id   TEXT NOT NULL REFERENCES member(id),
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
  wrapped_cek BLOB NOT NULL,
  payload     BLOB NOT NULL,
  FOREIGN KEY (group_id, epoch_n) REFERENCES epoch(group_id, n)
);
CREATE INDEX IF NOT EXISTS note_group_created ON note (group_id, created_at DESC);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    # -- membres / clés ----------------------------------------------------- #
    def add_member(self, matricule: str, display_name: str) -> uuid.UUID:
        mid = uuid.uuid4()
        self.db.execute(
            "INSERT INTO member (id, matricule, display_name) VALUES (?,?,?)",
            (str(mid), matricule, display_name),
        )
        self.db.commit()
        return mid

    def add_key(
        self,
        member_id: uuid.UUID,
        age_recipient: str,
        ed25519_pub: bytes,
        wrapped_seed: bytes,
    ) -> uuid.UUID:
        kid = uuid.uuid4()
        self.db.execute(
            "UPDATE member_key SET active = 0 WHERE member_id = ?",
            (str(member_id),),
        )
        self.db.execute(
            "INSERT INTO member_key "
            "(id, member_id, age_recipient, ed25519_pub, wrapped_seed) "
            "VALUES (?,?,?,?,?)",
            (str(kid), str(member_id), age_recipient, ed25519_pub, wrapped_seed),
        )
        self.db.commit()
        return kid

    def member_by_matricule(self, matricule: str) -> sqlite3.Row:
        return self.db.execute(
            "SELECT * FROM member WHERE matricule = ?", (matricule,)
        ).fetchone()

    def key(self, key_id: uuid.UUID) -> sqlite3.Row:
        return self.db.execute(
            "SELECT mk.*, m.matricule FROM member_key mk "
            "JOIN member m ON m.id = mk.member_id WHERE mk.id = ?",
            (str(key_id),),
        ).fetchone()

    def keyblob(self, matricule: str) -> bytes:
        """GET /me/keyblob — le keyblob chiffré, donc public."""
        row = self.db.execute(
            "SELECT mk.wrapped_seed FROM member_key mk "
            "JOIN member m ON m.id = mk.member_id "
            "WHERE m.matricule = ? AND mk.active = 1",
            (matricule,),
        ).fetchone()
        return row["wrapped_seed"]

    # -- groupes / époques -------------------------------------------------- #
    def create_group(self, name: str) -> uuid.UUID:
        gid = uuid.uuid4()
        self.db.execute("INSERT INTO grp (id, name) VALUES (?,?)", (str(gid), name))
        self.db.commit()
        return gid

    def put_epoch(self, group_id: uuid.UUID, n: int, gk_envelope: bytes):
        self.db.execute(
            "INSERT INTO epoch (group_id, n, gk_envelope) VALUES (?,?,?)",
            (str(group_id), n, gk_envelope),
        )
        self.db.commit()

    def epochs(self, group_id: uuid.UUID) -> dict[int, bytes]:
        rows = self.db.execute(
            "SELECT n, gk_envelope FROM epoch WHERE group_id = ? ORDER BY n",
            (str(group_id),),
        ).fetchall()
        return {r["n"]: r["gk_envelope"] for r in rows}

    def current_epoch(self, group_id: uuid.UUID) -> int:
        return self.db.execute(
            "SELECT max(n) AS n FROM epoch WHERE group_id = ?", (str(group_id),)
        ).fetchone()["n"]

    # -- chaîne d'octrois --------------------------------------------------- #
    def append_grant(
        self,
        group_id: uuid.UUID,
        seq: int,
        stmt: bytes,
        sig: bytes,
        signer_key_id: uuid.UUID,
        hash_: bytes,
    ):
        self.db.execute(
            "INSERT INTO grant_stmt "
            "(group_id, seq, stmt, sig, signer_key_id, hash) VALUES (?,?,?,?,?,?)",
            (str(group_id), seq, stmt, sig, str(signer_key_id), hash_),
        )
        self.db.commit()

    def next_seq(self, group_id: uuid.UUID) -> int:
        n = self.db.execute(
            "SELECT max(seq) AS s FROM grant_stmt WHERE group_id = ?",
            (str(group_id),),
        ).fetchone()["s"]
        return 0 if n is None else n + 1

    def grants(self, group_id: uuid.UUID) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT g.*, mk.ed25519_pub AS signer_pub, m.matricule AS signer_matricule "
            "FROM grant_stmt g "
            "JOIN member_key mk ON mk.id = g.signer_key_id "
            "JOIN member m ON m.id = mk.member_id "
            "WHERE g.group_id = ? ORDER BY g.seq",
            (str(group_id),),
        ).fetchall()

    # -- notes -------------------------------------------------------------- #
    def put_note(
        self,
        note_id: uuid.UUID,
        group_id: uuid.UUID,
        epoch_n: int,
        author_id: uuid.UUID,
        wrapped_cek: bytes,
        payload: bytes,
    ):
        self.db.execute(
            "INSERT INTO note "
            "(id, group_id, epoch_n, author_id, wrapped_cek, payload) "
            "VALUES (?,?,?,?,?,?)",
            (str(note_id), str(group_id), epoch_n, str(author_id), wrapped_cek, payload),
        )
        self.db.commit()

    def notes(self, group_id: uuid.UUID) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM note WHERE group_id = ? ORDER BY created_at DESC",
            (str(group_id),),
        ).fetchall()
