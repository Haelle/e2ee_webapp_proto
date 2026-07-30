"""Point d'entrée FastAPI (SPEC §8).

Rappel de conception : le serveur ne fait que ranger et distribuer des blobs et
vérifier des *signatures*. Aucune bibliothèque de chiffrement de contenu ici.
Le contrôle d'accès limite la distribution des blobs, il ne protège pas le
contenu — c'est admis et documenté (SPEC §8).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from . import db
from .routers import auth, groups, members, notes
from .settings import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_schema()
    yield
    db.close()


app = FastAPI(title="E2EE group notes — lot 1", version="0.1.0", lifespan=lifespan)

# Cookie de session signé, httpOnly (SPEC §8).
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=settings.cookie_secure,
    same_site="lax",
)
# Le SPA vit sur une autre origine en dev : CORS avec credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(members.router)
app.include_router(groups.router)
app.include_router(notes.router)


@app.get("/healthz", tags=["meta"])
def healthz():
    return {"status": "ok"}
