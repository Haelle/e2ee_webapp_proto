"""Accès Postgres via psycopg3 + pool. Aucune ORM : le serveur ne fait que
ranger et relire des blobs (SPEC §5, §8)."""

from __future__ import annotations

import pathlib

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .settings import settings

_pool: ConnectionPool | None = None
SCHEMA = pathlib.Path(__file__).with_name("schema.sql")


def pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            settings.database_url,
            min_size=1,
            max_size=10,
            open=True,
            kwargs={"row_factory": dict_row},
        )
    return _pool


def init_schema() -> None:
    with pool().connection() as conn:
        conn.execute(SCHEMA.read_text())


def close() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


if __name__ == "__main__":  # `poe initdb`
    init_schema()
    print("schéma initialisé sur", settings.database_url.rsplit("@", 1)[-1])
