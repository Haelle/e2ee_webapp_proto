# SPEC — Démo E2EE par groupes (Postgres / FastAPI / Svelte)

## 1. Objectif

Application volontairement minimale — des notes partagées — servant à valider le modèle
de chiffrement de bout en bout par groupe coopté, avant tout investissement sur la carte
à puce.

Ce qui doit être démontré, et rien d'autre :

1. Le serveur ne peut pas lire le contenu des notes.
2. Un membre coopté accède au groupe sans qu'aucune donnée ne soit retouchée.
3. La liste des membres est reconstruite depuis une chaîne signée, pas lue dans une table.
4. Un changement d'époque coupe l'accès aux écritures futures sans rechiffrer le passé.

Critère de réussite : `pg_dump` de la base, inspection manuelle, aucun contenu lisible ;
et un client capable de rejouer la chaîne d'octrois pour reconstituer la composition du
groupe sans faire confiance au serveur.

## 2. Hors périmètre

Explicitement exclus de cette itération, avec le point d'accroche prévu :

| Exclu | Accroche prévue |
|---|---|
| Carte à puce / PKCS#11 | Le déverrouillage du keyblob est isolé dans une seule fonction |
| Quorum M-of-N à la cooptation | La vérification de politique est isolée dans `checkPolicy()` |
| Blind index / recherche | Colonne à ajouter, cf. §12 lot 4 |
| Une note dans plusieurs groupes | La CEK existe déjà, il suffit de wrapper N fois |
| Clé de recours organisationnelle | Un destinataire `age` supplémentaire sur l'enveloppe d'époque |
| PKI X.509 | L'identité est ici une clé publique enrôlée hors bande |

## 3. Modèle de clés

Quatre niveaux. Chaque niveau ne sert qu'à ouvrir le suivant.

| Clé | Nature | Où elle vit | Générée par |
|---|---|---|---|
| Passphrase | Saisie utilisateur | Nulle part | L'utilisateur |
| Keyblob (PK) | Paire X25519 (age) + paire Ed25519 | Stocké chiffré sur le serveur | Le client, à l'enrôlement |
| GK | 32 octets symétriques, une par groupe et par époque | Enveloppe `age` sur le serveur | Le client, par un membre |
| CEK | 32 octets symétriques, une par note | Wrappée sous la GK, à côté de la note | Le client, à l'écriture |

La passphrase est le seul élément non stocké. Elle sera remplacée par la carte sans
toucher aux trois autres niveaux — c'est tout l'intérêt du keyblob intermédiaire.

Le keyblob est un JSON contenant l'identité `age` et la clé secrète Ed25519, chiffré en
**mode passphrase de `age`** (scrypt). Aucune dérivation maison.

## 4. Bibliothèques

Toute la cryptographie est déléguée. Aucune primitive n'est réimplémentée, aucune
sérialisation canonique n'est écrite à la main.

**Client (SvelteKit)**

| Usage | Bibliothèque |
|---|---|
| Enveloppe GK multi-destinataires, keyblob | `age-encryption` (npm) |
| AEAD notes et wrap CEK, Ed25519 | `libsodium-wrappers-sumo` |
| Sérialisation des déclarations signées | `cbor-x` |

**Serveur (FastAPI)**

| Usage | Bibliothèque |
|---|---|
| Vérification Ed25519 (structurelle uniquement) | `pynacl` |
| Décodage CBOR (lecture seule, jamais réencodé) | `cbor2` |

**Outil hors ligne (CLI Python, lot 0)**

`pyrage`, `pynacl`, `cbor2` — pour la genèse d'un groupe et le déchiffrement de secours.

> Épingler les versions dès le premier commit. Vérifier l'API exacte de
> `age-encryption` au moment de l'implémentation, elle a bougé entre versions majeures.

Le point notable : **le serveur n'a besoin d'aucune bibliothèque de chiffrement.**
Uniquement de la vérification de signature, et même celle-là est optionnelle. Si tu te
surprends à ajouter `cryptography` côté FastAPI, c'est le signe d'une erreur de
conception.

## 5. Schéma Postgres

```sql
CREATE TABLE member (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matricule    text UNIQUE NOT NULL,        -- identité stable, survit au renouvellement de clé
  display_name text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE member_key (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  member_id     uuid NOT NULL REFERENCES member(id),
  age_recipient text  NOT NULL,             -- "age1..."
  ed25519_pub   bytea NOT NULL,
  wrapped_seed  bytea NOT NULL,             -- keyblob, age mode passphrase
  active        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ON member_key (member_id) WHERE active;

CREATE TABLE grp (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text UNIQUE NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE epoch (
  group_id     uuid NOT NULL REFERENCES grp(id),
  n            int  NOT NULL,
  gk_envelope  bytea NOT NULL,              -- age, GK chiffrée vers tous les membres
  created_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, n)
);

CREATE TABLE grant_stmt (
  group_id      uuid  NOT NULL REFERENCES grp(id),
  seq           int   NOT NULL,
  stmt          bytea NOT NULL,             -- CBOR, octets exacts signés
  sig           bytea NOT NULL,
  signer_key_id uuid  NOT NULL REFERENCES member_key(id),
  hash          bytea NOT NULL,             -- blake2b-256(stmt)
  PRIMARY KEY (group_id, seq)
);

CREATE TABLE note (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  group_id    uuid NOT NULL REFERENCES grp(id),
  epoch_n     int  NOT NULL,
  author_id   uuid NOT NULL REFERENCES member(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  wrapped_cek bytea NOT NULL,
  payload     bytea NOT NULL,               -- AEAD, seul champ opaque
  FOREIGN KEY (group_id, epoch_n) REFERENCES epoch(group_id, n)
);
CREATE INDEX ON note (group_id, created_at DESC);
```

Deux décisions à noter :

- **Une enveloppe par époque, pas une par membre.** `age` gère nativement les N
  destinataires dans un seul blob. Coopter revient à réécrire cette ligne avec un
  destinataire de plus.
- **`matricule` est l'identité, pas la clé.** Une rotation de clé crée un
  `member_key`, jamais un `member`. C'est ce qui préserve la continuité d'appartenance
  au renouvellement de carte.

## 6. Format des blobs

**Keyblob** — `age` mode passphrase, contenu :

```json
{ "v": 1, "age_identity": "AGE-SECRET-KEY-1...", "ed25519_sk": "<base64>" }
```

**Enveloppe d'époque** — `age` mode destinataires, contenu = les 32 octets bruts de la GK.

**`wrapped_cek`** — `crypto_aead_xchacha20poly1305_ietf`, clé = GK, `ad = note_id`.
Format : `nonce(24) || ciphertext`.

**`payload`** — même primitive, clé = CEK, `ad = note_id || group_id || epoch_n`.
Contenu clair : `{ "title": "...", "body": "..." }`.

L'AAD n'est pas décoratif : sans lui, l'admin peut déplacer un `payload` d'une ligne vers
une autre, et le déchiffrement réussirait. Le test de non-régression correspondant est
listé en §11.

## 7. Chaîne d'octrois

Déclaration CBOR :

```
{
  v:       1,
  group:   <uuid>,
  action:  "found" | "add" | "remove",
  epoch:   <int>,               -- époque à laquelle la déclaration s'applique
  subject: <matricule>,
  key_id:  <uuid member_key>,   -- null si action == "remove"
  env:     <blake2b-256 de gk_envelope>,
  prev:    <hash du stmt précédent, null si seq == 0>,
  ts:      <unix>
}
```

**Règle absolue : on signe et on stocke les mêmes octets.** Le champ `stmt` contient le
CBOR exact ; la signature porte dessus ; on ne réencode jamais. Ça élimine toute la
question de la sérialisation canonique.

**Vérification côté client** (autorité) — rejeu depuis `seq = 0` :

```
members = {}
for each stmt in chain:
    assert stmt.prev == hash(previous)
    assert verify(signer.ed25519_pub, stmt, sig)
    if seq > 0: assert signer.matricule in members     # politique, lot 3 pour le quorum
    apply(stmt.action, stmt.subject)
    assert stmt.env == blake2b(epoch[stmt.epoch].gk_envelope)
```

**Vérification côté serveur** (confort) — `seq` incrémental, `prev` chaîné, signature
valide, signataire connu. Le serveur rejette les déclarations mal formées ; il n'a aucune
autorité sur la politique. Le client revérifie systématiquement, y compris ce que le
serveur a déjà validé.

## 8. API

Session par cookie `httpOnly` après authentification par défi-réponse Ed25519 — pas de
mot de passe côté serveur, et ça préfigure directement la carte.

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/auth/challenge` | `{matricule}` → nonce |
| POST | `/auth/verify` | `{matricule, sig}` → cookie de session |
| GET | `/me/keyblob` | Renvoie `wrapped_seed` (chiffré, donc public) |
| POST | `/members` | Enrôlement : `age_recipient`, `ed25519_pub`, `wrapped_seed` |
| POST | `/members/me/keys` | Rotation de clé personnelle |
| GET | `/groups` | Vue serveur, **indicative** |
| GET | `/groups/{id}/epochs` | Enveloppes GK, toutes époques |
| POST | `/groups/{id}/epochs` | Nouvelle époque : enveloppe + déclaration associée |
| GET | `/groups/{id}/grants` | Chaîne complète |
| POST | `/groups/{id}/grants` | Ajout en fin de chaîne |
| GET | `/notes?group_id=` | Métadonnées + blobs |
| POST | `/notes` | `wrapped_cek`, `payload`, `epoch_n` |
| PATCH | `/notes/{id}` | Idem |

Le contrôle d'accès serveur sert à limiter la distribution des blobs, pas à protéger le
contenu. Il est contournable par quiconque tient le serveur — c'est admis et documenté.

## 9. Front SvelteKit

Un store `session` détenant `{ ageIdentity, ed25519Sk, gks: Map<[groupId, epoch], CryptoKey> }`,
en mémoire uniquement. Aucune écriture en `localStorage` ni `IndexedDB` dans cette
itération : à la fermeture de l'onglet, tout est perdu et on ressaisit la passphrase.

Un module `crypto/` isolant strictement quatre fonctions, qui sont les seules à manipuler
du secret :

```ts
unlockKeyblob(passphrase, wrappedSeed)   // ← seul point à remplacer par la carte
openEpoch(ageIdentity, envelope)         // → GK
sealNote(gk, noteId, groupId, epoch, content)
openNote(gk, note)
```

Une fois la GK obtenue, l'importer non-extractible et effacer le buffer source. Une XSS
pourra l'utiliser le temps de la session, mais pas l'exfiltrer.

Le reste de l'application ignore tout du chiffrement et manipule des objets clairs.

## 10. Flux

**Enrôlement.** Le client génère l'identité `age` et la paire Ed25519, chiffre le keyblob
sous la passphrase, envoie les parties publiques et le keyblob chiffré. Le serveur ne
reçoit rien d'exploitable.

**Ouverture de session.** Défi-réponse Ed25519 → cookie. `GET /me/keyblob`, déverrouillage
par passphrase. `GET /groups/{id}/epochs`, ouverture de chaque enveloppe avec l'identité
`age` → toutes les GK en mémoire.

**Lecture.** `GET /notes` → pour chaque note, déwrap de la CEK sous la GK de son époque,
puis déchiffrement. Aucun appel serveur supplémentaire.

**Écriture.** CEK aléatoire, chiffrement du contenu, wrap de la CEK sous la GK de
l'époque **courante**, `POST`.

**Cooptation.** Le coopteur ouvre l'enveloppe de l'époque courante, récupère la GK, la
réencode en `age` vers l'ensemble des destinataires plus le nouveau, signe une
déclaration `add`, poste enveloppe et déclaration. Les notes ne sont pas touchées.
Choix explicite : rewrapper aussi les époques antérieures donne accès à l'historique, ne
rewrapper que la courante ne donne que le futur.

**Radiation.** GK neuve, nouvelle époque, enveloppe vers les membres restants uniquement,
déclaration `remove`. Les époques antérieures restent en place et restent lisibles par le
partant — c'est le comportement attendu, pas un défaut.

**Rotation de clé personnelle.** Nouveau keyblob, nouveau `member_key`, puis un membre
(ou l'intéressé lui-même s'il détient encore l'ancienne clé) réécrit les enveloppes
d'époque concernées. C'est le mécanisme qui coupera l'accès au passé lors d'un changement
de groupe.

## 11. Vérifications

À implémenter comme tests, pas comme intentions :

1. `pg_dump` puis `grep` sur un contenu connu → aucune occurrence.
2. Un membre de l'époque 3 ne peut pas ouvrir l'enveloppe de l'époque 4.
3. Échange de deux `payload` entre lignes en SQL direct → le déchiffrement échoue (AAD).
4. Une déclaration signée par un non-membre est rejetée au rejeu client, même si le
   serveur l'a acceptée — à tester en insérant directement en base.
5. Modification d'un `stmt` en base → la chaîne casse au `prev` suivant.
6. Un membre coopté après coup lit l'historique si et seulement si les anciennes
   enveloppes ont été rewrappées vers lui.
7. Le CLI hors ligne du lot 0 déchiffre un dump sans le serveur.

Le test 4 est le plus important : c'est celui qui prouve que l'autorité est côté client.

## 12. Lots

**Lot 0 — CLI Python, SQLite, aucun réseau.** Trois membres simulés, clés en fichiers.
Genèse d'un groupe, écriture, cooptation, changement d'époque, rejeu de chaîne. Objectif :
valider le modèle avant toute plomberie web. Environ 250 lignes. Le CLI reste ensuite
l'outil de secours mentionné au test 7.

**Lot 1 — FastAPI + Postgres.** Portage du lot 0 côté serveur, endpoints, auth par défi
Ed25519. Le client reste le CLI.

**Lot 2 — SvelteKit.** Module `crypto/`, store de session, écrans de liste et d'édition,
écran de cooptation.

**Lot 3 — Politique.** Quorum M-of-N, rotation de clé personnelle, cas de bord de la
chaîne.

**Lot 4 — Optionnel.** Blind index sur le titre (`HMAC(HKDF(GK, "bi"), lower(title))`,
colonne `title_bi bytea`), note multi-groupes.

L'ordre est contraignant. Commencer par le lot 2 revient à déboguer simultanément le
modèle et WebCrypto.

## 13. Pièges connus

- **Versionner le format d'enveloppe** dès le premier octet écrit. Un champ `v` dans
  chaque blob. Sans ça, la première évolution rend la base illisible.
- **Ne jamais réencoder un CBOR signé.** Stocker et vérifier les octets d'origine.
- **`age` renvoie du binaire.** Ne pas passer par de l'armor ASCII pour du `bytea`.
- **Nonce aléatoire, jamais de compteur.** XChaCha20 a un nonce de 24 octets précisément
  pour que l'aléatoire soit sûr.
- **Effacer les buffers de clé** après import non-extractible.
- **La vue serveur des groupes est indicative.** Si un écran l'affiche comme vérité,
  l'incohérence avec le rejeu de chaîne finira par se produire et ne sera pas détectée.
