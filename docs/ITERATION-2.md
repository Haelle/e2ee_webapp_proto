# Itération 2 — lot 2 terminé (front SvelteKit)

Suite de l'itération 1. Objectif : **rendre la démo complète et vérifiable dans
le navigateur** — cooptation, radiation, et surtout le **rejeu de chaîne côté
client** (l'autorité, SPEC §3, §7, §13) visible à l'utilisateur.

## 1. Ce qui a été ajouté

### Front (`web/`)
- **`crypto/replay.ts`** — le rejeu de chaîne, **l'autorité**. Reconstruit la
  composition depuis la chaîne signée. Point clé : le signataire de chaque
  déclaration est résolu en matricule via les liaisons `key_id → subject` de la
  **chaîne elle-même**, pas via le champ `signerMatricule` du serveur. Une
  déclaration signée par un non-membre est donc rejetée même si le serveur l'a
  acceptée et ment sur le signataire (test §11.4, porté côté client).
- **`crypto/` (ajouts)** : `newGk`, `sealEpoch` (enveloppe age multi-destinataires),
  et l'effacement du buffer de clé dans `unlockKeyblob` (`sodium.memzero`).
- **`group.ts`** — opérations de haut niveau (SPEC §10) : `foundGroup`,
  `coopt`, `removeMember`, `loadGroup` (rejeu + ouverture des GK accessibles).
- **Écrans** : `/groups` (liste + genèse) et `/groups/[id]` (composition issue
  du rejeu avec **trace de vérification** par maillon, cooptation, radiation,
  notes CRUD dont l'édition PATCH).
- **Tests** : `crypto/replay.test.ts` (Vitest, 4 cas : chaîne valide, non-membre
  §11.4, stmt falsifié §11.5, env qui ne correspond pas) + `e2e/coopt.integration.spec.ts`
  (Playwright bout-en-bout contre un vrai backend, guardé par `E2E_BACKEND`).

### Back (`server/`) — compléments nécessaires au navigateur
- **`GET /members/{matricule}`** — matériel public d'un membre (age_recipient,
  ed25519_pub, key_id), nécessaire au coopteur pour rewrapper l'enveloppe.
- **`PUT /groups/{id}/epochs/{n}`** — cooptation : réécrit l'enveloppe de
  l'époque courante *en place* + déclaration `add` (l'API append-only ne le
  permettait pas). La radiation continue de passer par `POST /epochs` (nouvelle
  époque) + déclaration `remove`.
- **`GET /members/{matricule}/keyblob`** — keyblob **public** (chiffré) et
  **sans session** : voir le correctif ci-dessous.
- Nouveau test `test_coopt_then_remove_lifecycle` : cooptation (PUT) → radiation
  (POST) → rejeu de chaîne à chaque étape.

## 2. Un bug réel corrigé — bootstrap de session

Le flux de connexion posé au lot 1 appelait `GET /me/keyblob` (protégé par
session) **avant** de s'authentifier. Or il faut la clé Ed25519 du keyblob pour
répondre au défi : impossible d'avoir la session avant d'avoir le keyblob. Le
front ayant été bâti sans backend, ce bug n'avait jamais été exécuté.

Correctif conforme à la SPEC (§8 : *« wrapped_seed, chiffré, donc public »*) :
le keyblob est désormais récupérable **sans session, par matricule**
(`GET /members/{matricule}/keyblob`). L'ordre de connexion devient : défi →
keyblob public → déverrouillage → signature → vérification → cookie.

## 3. Écarts / limites assumés (à revoir)

- **GK non-extractible (SPEC §9) : non réalisable tel quel.** La SPEC demande
  d'importer la GK en `CryptoKey` non-extractible, mais §6 impose
  XChaCha20-Poly1305, absent de WebCrypto (qui n'a qu'AES-GCM). La GK reste donc
  des octets en mémoire (libsodium). L'effacement des buffers est fait là où
  c'est possible ; les `string` JS (identité age, seed hex) ne sont pas
  effaçables — c'est exactement ce que la carte à puce résout (le seed
  n'atteint jamais JS). *Décision à valider : garder XChaCha20 + octets, ou
  passer la GK en AES-GCM WebCrypto pour la non-extractibilité ?*
- **cbor-x en options non par défaut** (déjà signalé itér. 1) : la compat avec
  `cbor2` reste tributaire de `useRecords:false, tagUint8Array:false`.
- **Cooptation = rewrap de l'époque courante uniquement** (le nouveau voit le
  présent, pas l'historique profond). Le rewrap d'historique existe dans le
  modèle (lot 0) mais n'est pas exposé à l'écran.
- La **résolution des destinataires** se fait par N appels `GET /members/{m}` ;
  acceptable pour la démo, à grouper plus tard.

## 4. Reporté (lot 3)

Rotation de clé personnelle (avec re-pin d'enveloppe), quorum M-of-N via le
crochet `check_policy` déjà présent dans le rejeu, cas de bord de la chaîne,
rewrap d'historique à l'écran.

## 5. Vérifications (toutes vertes)

| Suite | Ce qu'elle prouve |
|---|---|
| `server` pytest (4) | contrat HTTP + cooptation/radiation + rejeu (client = `lot0.model`) |
| `web` Vitest (4) | autorité du rejeu : non-membre rejeté, stmt falsifié, env |
| `web` Playwright smoke | rendu de l'app (sans backend, défaut CI) |
| `web` Playwright intégration | enrôlement → genèse → note → **cooptation** en vrai navigateur contre le backend (`E2E_BACKEND=1`) |
| `lot0` demo | les 7 vérifications §11 (inchangé) |

CI : le job frontend lance désormais aussi Vitest (`pnpm test:unit`). Le test
d'intégration reste hors CI (pas de backend dans ce job) mais tourne en local.
