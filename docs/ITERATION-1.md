# Itération 1 — document de revue

Première itération de la webapp E2EE par groupes (au-delà de la démo hors ligne
du lot 0). Objectif : **poser le squelette complet et réviser l'architecture et
la chaîne d'outils** avant d'investir dans les écrans et la politique.

Ce document est destiné à la **revue**. Il dit ce qui est fait, ce qui est
vérifié, les écarts assumés par rapport à la SPEC, et ce qui est reporté.

---

## 1. Périmètre de l'itération

| Composant | État | Vérifié |
|---|---|---|
| `lot0/` — démo hors ligne | inchangé, conservé comme outil de secours | 7/7 checks §11 |
| `server/` — FastAPI + Postgres (lot 1) | **fonctionnel** | pytest vert, boot OK |
| `web/` — SvelteKit SPA (lot 2, amorce) | **build vert**, écrans minimaux | build + check + e2e |
| `deploy/` — Podman/k8s hot reload | manifeste validé (non exécuté ici) | YAML validé |
| `.devcontainer/` — Podman | défini | — |

Ce qui est **délibérément minimal** en itération 1 : les écrans du front
(connexion + liste/création de notes), pas encore de cooptation/rotation à
l'écran ni de rejeu de chaîne côté navigateur. Voir §6.

---

## 2. Architecture (monorepo)

```
e2ee_webapp_proto/
├── lot0/          # démo Python hors ligne — modèle + outil de secours (§11.7)
├── server/        # FastAPI : range des blobs, vérifie des signatures. AUCUNE crypto de contenu.
├── web/           # SvelteKit SPA : tout le chiffrement vit ici (module crypto/)
├── deploy/        # manifeste k8s de dev (podman kube play), hot reload
├── .devcontainer/ # env de dev Podman (uv/poe, node/pnpm, psql, playwright)
└── docs/          # ce document
```

Frontière de confiance (SPEC §1) : **le serveur ne voit que des octets
opaques**. L'autorité sur la composition d'un groupe est le **rejeu de la chaîne
signée**, côté client. Le contrôle d'accès serveur ne fait que limiter la
distribution des blobs (§8).

### Modèle de clés (rappel §3)

```
passphrase ─▶ keyblob (age X25519 + Ed25519) ─▶ GK (par groupe/époque) ─▶ CEK (par note) ─▶ payload
```

`unlockKeyblob` (front) / `unlock_keyblob` (lot0) est le **seul** point que la
carte à puce remplacera.

---

## 3. Chaîne d'outils

| Domaine | Choix | Où |
|---|---|---|
| Deps Python | **uv** (lock épinglé) | `server/pyproject.toml`, `server/uv.lock` |
| Tâches | **poe** (poethepoet) | `[tool.poe.tasks]` |
| Web | SvelteKit **SPA** (adapter-static, `ssr=false`) | `web/` |
| UI | **Tailwind v4** + **shadcn-svelte** | `web/src/lib/components/ui` |
| Tests serveur | pytest (client = `lot0.model`) | `server/tests` |
| Tests front | **Playwright** | `web/e2e` |
| Base | **PostgreSQL 16** | schéma §5 dans `server/app/schema.sql` |
| Conteneurs | **Podman**, manifeste **Kubernetes**, hot reload | `deploy/`, `.devcontainer/` |

### Versions épinglées (extraits)

- Serveur : fastapi 0.115.6, uvicorn 0.34.0, psycopg 3.2.4, pynacl 1.6.2,
  cbor2 6.1.3. Dev : poethepoet 0.32.1, pytest 8.3.4, ruff 0.9.2, pyrage 1.3.0.
- Front : svelte 5.56, @sveltejs/kit 2.70, vite 8.2, adapter-static 3.0.10,
  tailwindcss 4.3.3, shadcn-svelte (CLI) 1.4.2. Crypto :
  **age-encryption 0.3.0**, **libsodium-wrappers-sumo 0.8.4**, **cbor-x 1.6.5**.

---

## 4. Ce qui est fait, par composant

### 4.1 `server/` (lot 1)

- **Endpoints §8** : auth défi-réponse Ed25519 (`/auth/challenge`, `/verify`,
  `/logout`), `/me/keyblob`, `/members` + rotation, `/groups` + époques +
  grants, `/notes` (GET/POST/PATCH). Sessions par **cookie signé httpOnly**.
- **Postgres via psycopg3**, pas d'ORM ; schéma §5 tel quel.
- **Vérification structurelle** de la chaîne (§7 « confort ») dans `app/chain.py`
  : seq incrémental, `prev` chaîné, signature valide, signataire connu,
  fondation en seq 0. **Jamais** de vérification de politique — c'est le client
  qui rejoue et fait autorité (test §11.4). Le serveur **stocke les octets CBOR
  exacts reçus**, jamais réencodés (§7, §13).
- **Rappel §4 respecté** : aucune bibliothèque de chiffrement côté serveur ;
  `pynacl` ne sert qu'à vérifier des signatures, `cbor2` décode en lecture
  seule. Pas de `cryptography`.

**Tests (`server/tests`)** — le client de test est **`lot0.model`**, donc les
tests prouvent à la fois le contrat HTTP *et* la compatibilité de format entre
le client Python (l'outil de secours) et le serveur :
- `test_full_flow` : enrôlement → session → genèse (groupe + époque 0 +
  fondation) → écriture d'une note scellée → relecture et déchiffrement → rejeu
  de la chaîne (= {MAT-A}).
- `test_requires_auth` : 401 sans session.
- `test_server_rejects_malformed_grant` : signature invalide → 400.

### 4.2 `web/` (lot 2, amorce)

- **SPA** (adapter-static, `fallback: index.html`, `ssr=false`,
  `prerender=false`). Tailwind v4 + shadcn-svelte.
- **Module `crypto/`** — les quatre fonctions §9 + les primitives de chaîne
  (`buildStmt`, `signStmt`, `blake2b256`, `signChallenge`). Round-trips vérifiés
  contre les vraies bibliothèques ; **`buildStmt` produit un CBOR identique
  octet-pour-octet à `cbor2.dumps` de Python** → l'outil de secours du lot 0
  reste compatible.
- **Store de session** en mémoire uniquement (aucun localStorage/IndexedDB, §9).
- **Client API** typé, base64 sur le fil, `credentials: 'include'`.
- **Écrans** : connexion/enrôlement (`/`), liste + création de notes
  (`/notes`). Minimalistes mais réels.
- **Playwright** : test de fumée (build + preview + rendu de la home).

### 4.3 `deploy/` + `.devcontainer/`

- **Manifeste Kubernetes de dev** jouable par `podman kube play` : Postgres +
  serveur + front (3 `Deployment`, 3 `Service`, 1 `PVC`). **Rechargement à
  chaud** par montage `hostPath` du code + volumes masquant `.venv`/
  `node_modules`. `dev-up.sh` rend le gabarit (`__REPO_ROOT__`), construit les
  images et lance ; `dev-down.sh` nettoie.
- **Devcontainer Podman** avec toute la chaîne d'outils.
- *Non exécuté dans cet environnement* (podman/kubectl absents) ; le YAML rendu
  est validé (7 documents, kinds attendus, substitution OK).

---

## 5. Écarts assumés par rapport à la SPEC (à revoir)

1. **`POST /groups`** ajouté : §8 ne prévoit pas de création de groupe.
   L'UUID est **fourni par le client** pour que la déclaration `found` puisse le
   référencer. → *Point de revue : est-ce le bon découpage, ou faut-il fondre la
   création dans le premier `POST /epochs` ?*
2. **`POST /notes` exige un `id` client** : le `payload` est scellé avant envoi
   et son AAD lie le chiffré à cet `id` (§6). Le serveur ne génère donc pas l'id.
3. **`cbor-x` en options non par défaut** (`useRecords:false`,
   `tagUint8Array:false`, `variableMapSize:true`) : indispensable pour reproduire
   les octets de `cbor2`. Sans ça, les défauts de cbor-x émettent des tags que
   Python ne décode pas. Documenté dans `web/README.md`.
4. **Enveloppe d'époque réécrite en place à la cooption** : le rejeu ne vérifie
   `env` que pour la **dernière** déclaration visant une époque (les précédentes
   restent couvertes par signature + chaînage). Déjà acté au lot 0 ; à garder à
   l'esprit pour le portage front de la cooptation.
5. `POST /auth/logout` ajouté (confort).

---

## 6. Reporté aux itérations suivantes

- **Front** : écrans de cooptation / radiation / rotation, **rejeu de chaîne
  côté navigateur** (l'autorité doit y être visible à l'utilisateur, §13), édition
  de note (PATCH). `buildStmt`/`signStmt` sont prêts mais pas câblés aux écrans.
- **GK non-extractible** : la GK est pour l'instant gardée en octets bruts ;
  l'import `CryptoKey` non-extractible + effacement des buffers (§9) est à faire.
- **Politique (lot 3)** : quorum M-of-N via le crochet `check_policy` déjà présent
  dans `replay_chain`, cas de bord de la chaîne, rotation avec rewrap d'enveloppes.
- **Prod** : les manifestes sont *dev-only* (hostPath, `--reload`, `pnpm dev`).
  Un vrai déploiement fige les images et retire le hot reload.
- **Vérifications §11 bout-en-bout sur Postgres** (dump/grep, échange de payload
  en SQL, stmt falsifié) : le lot 0 les couvre sur SQLite ; à rejouer sur PG.

---

## 7. Comment vérifier (revue locale)

```sh
# Backend
cd server && uv sync
uv run poe initdb          # nécessite un Postgres (voir .env.example)
uv run poe test            # 3 tests verts
uv run poe dev             # http://localhost:8000/docs

# Front
cd web && pnpm install
pnpm build                 # SPA statique → web/build
pnpm check                 # svelte-check : 0 erreur
pnpm test:e2e              # smoke Playwright

# Démo hors ligne (inchangée)
python -m lot0.demo        # 7/7 vérifications §11

# Pile complète (hôte avec podman)
deploy/dev-up.sh           # front :30173, api :8000, hot reload
```

---

## 8. Points d'attention pour le relecteur

- Le **découpage genèse** (`POST /groups` séparé) — §5.1 ci-dessus.
- La **compatibilité CBOR** JS↔Python repose sur des options non par défaut de
  cbor-x (§5.3) : c'est fragile par nature, à surveiller à chaque montée de
  version de `cbor-x`. Un test de non-régression « octets identiques » est en
  place côté agent mais **pas encore committé comme test automatisé** — à ajouter.
- Le serveur fait confiance au client pour l'`id` de note et l'`id` de groupe :
  cohérent avec « l'autorité est côté client », mais à garder explicite.
- Manifestes k8s **non exécutés** dans cet environnement (pas de podman/kubectl) ;
  la logique de hot reload (volumes masquants) mérite un test réel.
