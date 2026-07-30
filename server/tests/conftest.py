"""Fixtures de test : base isolée, tables vidées, client HTTP en process.

Le « client » de test réutilise le cœur crypto du lot 0 (`lot0.model`) : c'est
le même code qui sert d'outil de secours. Le test prouve donc à la fois le
contrat HTTP et la compatibilité de format entre client Python et serveur.
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

# base de test dédiée (surchargeable via l'environnement)
os.environ.setdefault(
    "E2EE_DATABASE_URL", "postgresql://e2ee:e2ee@127.0.0.1:5432/e2ee_test"
)
os.environ.setdefault("E2EE_SESSION_SECRET", "test-secret")

# rendre le paquet `lot0` importable (démo standalone conservée à la racine)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from app import db
    from app.main import app

    db.init_schema()
    with db.pool().connection() as conn:
        conn.execute(
            "TRUNCATE note, grant_stmt, epoch, member_key, grp, member RESTART IDENTITY CASCADE"
        )
    with TestClient(app) as c:
        yield c
