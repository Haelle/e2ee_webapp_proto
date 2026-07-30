# Serveur — Lot 1 (FastAPI + Postgres)

Portage du modèle du lot 0 côté serveur (SPEC §12, lot 1). Le serveur **range et
distribue des blobs** et **vérifie des signatures Ed25519** — rien d'autre.

> SPEC §4 : le serveur n'a besoin d'**aucune** bibliothèque de chiffrement.
> `pynacl` ne sert qu'à vérifier des signatures ; `cbor2` décode en lecture
> seule. Aucune `cryptography` ici — sa présence signalerait une erreur de
> conception.

## Pile

- **FastAPI** + **uvicorn**, sessions par cookie signé httpOnly.
- **Postgres** via **psycopg3** (pas d'ORM ; schéma §5 tel quel dans `app/schema.sql`).
- **uv** pour les dépendances, **poe** (poethepoet) comme lanceur de tâches.

## Tâches (poe)

```sh
uv sync            # installe tout (dont le groupe dev)
uv run poe initdb  # crée le schéma
uv run poe dev     # uvicorn --reload sur :8000
uv run poe test    # pytest
uv run poe lint    # ruff
```

## Structure

| Fichier | Rôle |
|---|---|
| `app/main.py` | Montage FastAPI, middlewares session + CORS. |
| `app/db.py` | Pool psycopg3, init du schéma. |
| `app/schema.sql` | Schéma Postgres (SPEC §5). |
| `app/auth.py` | Défi-réponse Ed25519, dépendance de session. |
| `app/chain.py` | Vérification **structurelle** de la chaîne (§7 « confort »). |
| `app/codec.py` | base64 ⇆ bytes, blake2b-256. |
| `app/routers/` | `auth`, `members`, `groups` (+ époques, grants), `notes`. |
| `tests/` | Scénario du lot 0 rejoué par-dessus l'API + auth + rejet structurel. |

## Points de conception

- **L'autorité est côté client.** Le serveur vérifie la *forme* d'une
  déclaration (seq, prev, signature, signataire connu) mais **jamais la
  politique** (qui peut coopter qui). Le client rejoue et revérifie tout
  (test §11.4).
- **On stocke les octets CBOR exacts reçus**, jamais réencodés (§7, §13).
- **Le contrôle d'accès limite la distribution des blobs**, il ne protège pas le
  contenu — contournable par qui tient le serveur, admis et documenté (§8).
- Les champs binaires transitent en **base64** dans le JSON.

## Écarts par rapport à §8 (documentés)

- **`POST /groups`** ajouté (l'UUID est fourni par le client pour que la
  déclaration `found` puisse le référencer) — §8 ne listait pas de création de
  groupe.
- **`POST /notes`** exige un `id` fourni par le client : le `payload` est scellé
  avant l'envoi et son AAD lie le chiffré à cet `id` (§6).
- `POST /auth/logout` ajouté (confort).

## Tests

Les tests utilisent `lot0.model` comme **client de référence** : ils prouvent le
contrat HTTP *et* la compatibilité de format entre le client Python (l'outil de
secours) et le serveur. Une base `e2ee_test` est attendue ; voir `.env.example`.
