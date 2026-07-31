# Démo E2EE par groupes

[![CI](https://github.com/Haelle/e2ee_webapp_proto/actions/workflows/ci.yml/badge.svg)](https://github.com/Haelle/e2ee_webapp_proto/actions/workflows/ci.yml)

Application minimale — des notes partagées — servant à valider un modèle de
chiffrement de bout en bout par **groupe coopté**, avant tout investissement sur
la carte à puce. Voir [`SPEC.md`](SPEC.md) pour le cahier des charges complet.

Ce qui doit être démontré, et rien d'autre :

1. Le serveur ne peut pas lire le contenu des notes.
2. Un membre coopté accède au groupe sans qu'aucune donnée ne soit retouchée.
3. La liste des membres est reconstruite depuis une chaîne signée, pas lue dans
   une table.
4. Un changement d'époque coupe l'accès aux écritures futures sans rechiffrer le
   passé.

## État d'avancement

L'ordre des lots est contraignant (SPEC §12) : commencer par le modèle, pas par
l'interface.

| Lot | Contenu | État |
|---|---|---|
| **0** | CLI Python / SQLite / hors ligne — modèle, rejeu de chaîne, secours | ✅ [`lot0/`](lot0/) |
| **1** | FastAPI + Postgres, auth par défi Ed25519 | ✅ [`server/`](server/) |
| **2** | SvelteKit SPA, `crypto/`, cooptation, rejeu de chaîne | ✅ [`web/`](web/) |
| 3 | Politique : quorum M-of-N, rotation de clé | à venir |
| 4 | Optionnel : blind index, note multi-groupes | à venir |

**Revue : [`docs/ITERATION-1.md`](docs/ITERATION-1.md) (squelette + lot 1) ·
[`docs/ITERATION-2.md`](docs/ITERATION-2.md) (lot 2 : cooptation + rejeu de chaîne).**

## Structure

| Dossier | Rôle |
|---|---|
| [`lot0/`](lot0/) | Démo Python hors ligne — le modèle et l'outil de secours (§11.7). |
| [`server/`](server/) | FastAPI + Postgres : range des blobs, vérifie des signatures. **Aucune crypto de contenu** (§4). |
| [`web/`](web/) | SvelteKit SPA : tout le chiffrement vit dans `src/lib/crypto/` (§9). |
| [`deploy/`](deploy/) | Manifeste Kubernetes de dev, jouable par **Podman**, rechargement à chaud. |
| `.devcontainer/` | Environnement de dev Podman (uv/poe, node/pnpm, psql, Playwright). |

## Démarrage rapide

```sh
# Démo hors ligne (aucune dépendance de service)
pip install -r lot0/requirements.txt && python -m lot0.demo   # 7/7 checks §11

# Backend (nécessite un Postgres — voir server/.env.example)
cd server && uv sync && uv run poe initdb && uv run poe dev    # :8000/docs

# Front (SPA)
cd web && pnpm install && pnpm dev                             # :5173

# Pile complète en conteneurs, hot reload (hôte avec podman)
deploy/dev-up.sh
```

Détails par composant dans les README de chaque dossier.
