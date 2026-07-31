# Glossaire & concepts — modélisation E2EE

Document de référence. Capitalise le vocabulaire et les concepts de conception du
projet (chiffrement de bout en bout par groupe). Chaque terme est, quand c'est
possible, rattaché à l'endroit du dépôt où il vit.

> Principe fondateur, à garder en tête partout : **le serveur ne lit rien.** Il
> ne peut indexer, contraindre (`enum`, `FOREIGN KEY`), filtrer ou joindre que ce
> qu'il voit **en clair**. Toute valeur qui doit rester secrète perd ces
> capacités-là — c'est le cœur de tous les arbitrages ci-dessous.

---

## 1. Vocabulaire

### Clés et identité

| Terme | Définition | Où dans le repo |
|---|---|---|
| **Passphrase** | Secret saisi par l'utilisateur, jamais stocké. Déverrouille le keyblob. Sera remplacée par la carte à puce. | — |
| **Keyblob** | JSON `{ v, age_identity, ed25519_sk }` chiffré **en mode passphrase de `age`** (scrypt). Contient l'identité `age` et la clé de signature Ed25519 d'un membre. | `crypto/index.ts` (`unlockKeyblob`), `lot0/model.py` |
| **Identité `age` (X25519)** | Paire de clés de chiffrement asymétrique. La partie publique est le **destinataire** (`age1…`). | keyblob |
| **Ed25519** | Paire de signature. Sert au défi-réponse d'auth et à **signer les déclarations** de la chaîne d'octroi. | `grant_stmt`, `/auth` |
| **GK** (*Group Key*) | 32 octets symétriques, **une par groupe et par époque**. Chiffre/wrappe le niveau du dessous. | enveloppe d'époque |
| **CEK** (*Content Encryption Key*) | 32 octets symétriques, **une par note (par valeur)**. Wrappée sous la GK, à côté de la donnée. | `wrapped_cek` |
| **Enveloppe (d'époque)** | Blob `age` **multi-destinataires** dont le clair est la GK (32 octets bruts). Coopter = réécrire cette ligne avec un destinataire de plus. | table `epoch.gk_envelope` |
| **`matricule`** | Identité **stable** d'un membre, en clair. Survit au renouvellement de clé (id ≠ clé). | table `member` |

### Primitives cryptographiques

| Terme | Définition |
|---|---|
| **AEAD** | *Authenticated Encryption with Associated Data* : chiffre **et** authentifie en une opération. Ici **XChaCha20-Poly1305 IETF** (nonce aléatoire de 24 octets). |
| **AAD** | *Additional Authenticated Data* : données **authentifiées mais non chiffrées**, mélangées au tag d'intégrité. Si elles diffèrent au déchiffrement, ça **échoue**. On lie chaque blob à sa ligne (`note_id \|\| group_id \|\| epoch_n`) → impossible de déplacer un ciphertext ailleurs. Non secret, mais infalsifiable et contextuel. |
| **Nonce** | Nombre utilisé une seule fois. XChaCha20 a un nonce de 24 octets **précisément pour qu'un tirage aléatoire soit sûr** — jamais de compteur. |
| **HKDF / KDF** | *(HMAC-based) Key Derivation Function* (RFC 5869). À partir d'**un** secret + un **label** (`"meta"`, `"bi"`, `"fk:A"`), dérive de façon **déterministe** des sous-clés indépendantes, sans les stocker. Sépare les usages d'une clé racine. En libsodium : `crypto_kdf_derive_from_key`. |
| **blake2b** | Fonction de hachage. Ici blake2b-256, seul hachage du projet (`env`, `prev`, `hash`). |
| **Chiffrement déterministe** | Même clair → même ciphertext. Permet l'égalité côté serveur, **au prix** d'une fuite du motif d'égalité (fréquence). |

### Construction de données chiffrées

| Terme | Définition |
|---|---|
| **Wrapping / chiffrement hybride (enveloppe)** | Chiffrer une **clé** sous une autre clé. La donnée est chiffrée une fois sous une CEK ; la CEK est *wrappée* sous une (ou plusieurs) GK. Ajouter un lecteur / tourner une clé = refaire un wrap, **sans retoucher le payload**. `age` fait ça pour la GK ; on l'applique un cran plus bas pour la CEK. |
| **Blind index** | Colonne `bytea` = `HMAC(HKDF(GK, "bi"), lower(valeur))`. Permet au serveur une **recherche par égalité** sur une valeur qu'il ne lit pas — au prix d'une fuite d'égalité/fréquence. À **saler par groupe/époque** ; dangereux sur faible cardinalité (enums). |
| **Multi-wrap** | La même CEK (donc la même valeur) wrappée sous **plusieurs GK**, pour des audiences disjointes. |
| **Octet de version (`v`)** | Préfixe **en clair** de chaque blob indiquant son **format**. Lisible par client *et* serveur, sans rien révéler du contenu. Indispensable à toute évolution de format (SPEC §13). |
| **Upcasting** | Migration **par enregistrement** : une chaîne de fonctions `v_n → v_{n+1}` (pattern *event-sourcing*), appliquée à la lecture quand un blob est en version ancienne. À ne pas confondre avec une migration de schéma (tête globale unique). |
| **Crypto-shredding** | « Supprimer » une donnée chiffrée en **détruisant sa clé** (ex. changement d'époque pour un membre radié), sans réécrire le ciphertext. |

### Autorité et politique

| Terme | Définition | Où |
|---|---|---|
| **Chaîne d'octroi** (*grant chain*) | Suite de déclarations CBOR signées (`found`/`add`/`remove`), chaînées par `prev`. **Reconstruit la composition du groupe** ; c'est **l'autorité**, pas la vue serveur. | `grant_stmt`, `crypto/replay.ts` |
| **Époque** (*epoch*) | Version de la GK d'un groupe. Radiation = nouvelle époque ; cooptation = réécriture de l'enveloppe de l'époque courante. | table `epoch` |
| **Métadonnée de routage** | Champ laissé **en clair volontairement** parce que le serveur en a besoin (distribution des blobs, contrôle d'accès grossier). Fuite admise et documentée (SPEC §8). | `note.group_id`, `note.epoch_n`, `grant.signer_key_id` |
| **Compartimentage / partition de clés** | Séparer les données en classes chiffrées sous des clés distinctes, pour un accès ou un rayon d'explosion différenciés. | (concept, cf. §5) |

### Ingénierie

| Terme | Définition |
|---|---|
| **YAGNI** | *You Aren't Gonna Need It* — ne construis pas une abstraction (ex. multiplier les GK) avant d'en avoir le besoin réel. |

---

## 2. Le principe des trois cases

Pour **chaque champ** (et chaque lien), choisir une case — on ne peut pas être
« secret **et** interrogeable » gratuitement :

| Case | Où vit la valeur | Le serveur voit | Ce qu'on garde |
|---|---|---|---|
| **Métadonnée de routage** | colonne en clair | la valeur | `enum`, FK, index, join, contrainte |
| **Confidentiel** | dans le payload chiffré | rien (blob opaque) | rien côté serveur → tout passe **au client** |
| **Compromis** | jeton dérivé de clé (blind index, déterministe) | l'égalité / la structure | égalité, `GROUP BY`, traversée — au **prix** d'une fuite mesurée |

Corollaire : pour tout ce qui est **confidentiel**, la **validation** (domaine d'un
enum, intégrité d'une FK) devient une **responsabilité du client**, re-vérifiée —
comme le rejeu de chaîne est l'autorité. Le serveur ne garantit que ce qu'il voit.

---

## 3. Enums et liens chiffrés

**Enum confidentiel** → dans le payload (`{"status":"urgent"}`) ; domaine validé
côté client ; **padding** à longueur fixe (sinon la longueur fuit la valeur) ;
AAD pour le lier à sa ligne. Si le serveur doit grouper/filtrer sans lire :
blind-index salé par groupe — mais faible cardinalité = forte fuite de fréquence.

**Lien confidentiel** → la question : *l'existence du lien est-elle sensible ?*
- Non (routage) → **FK en clair** (ce qu'on fait pour `group_id`, `epoch_n`).
- Oui → la **FK vit dans le payload chiffré** ; le `JOIN` et l'intégrité
  référentielle passent **au client** (liens pendouillants tolérés). Variante :
  **jetons d'arête pseudonymes** si le serveur doit traverser (fuite de la *forme*
  du graphe).

Notre `grant_stmt` est **le lien chiffré bien fait** : l'appartenance n'est pas
une table de FK, c'est une relation **signée, opaque au serveur**, dont l'autorité
est reconstruite par le client.

---

## 4. Charger un objet : par étapes

Les FK confidentielles étant dans le chiffré, le serveur ne peut pas joindre. Le
client résout **par couches** : déchiffre D → lit les `id` de A/B → `GET` A/B par
id clair → déchiffre. En pratique, pour éviter le N+1 :

1. **Bulk-load des référentiels** (petits, faible cardinalité) : le client
   déchiffre toute la table A/B/C une fois, garde une map `id → objet`, résout les
   FK **localement**. *Le* levier.
2. **Endpoints multi-get** (`GET /refs?ids=…`) : une requête par couche.
3. **Dénormalisation** : embarquer une copie de la valeur dans le blob (zéro
   seconde lecture, au prix d'un fan-out de mise à jour).

En somme : on **réimplémente le eager-loading côté client** (identity-map sur des
dictionnaires déchiffrés).

---

## 5. Hiérarchie et partition de clés

Plusieurs GK par **classe** de données (ex. `GK-meta` pour les référentiels,
`GK-data` pour la donnée). Deux façons :

| | GK **indépendantes** | Sous-clés **dérivées** `HKDF(GK_root, label)` |
|---|---|---|
| Accès différencié par classe | ✅ | ❌ (même audience) |
| Rotation | indépendante | couplée au root |
| Coût distribution | N enveloppes/époque | 1 enveloppe, N sous-clés |

**Règle (YAGNI)** : GK indépendantes **seulement** si l'accès ou le rayon
d'explosion diffèrent par classe ; sinon, séparation de domaine par label HKDF.

**Référentiels** : `id` en clair (UUID aléatoire, ne révèle rien) + contenu
chiffré (GK-meta). Les IDs clairs sont ce qui rend l'**encrypted FK** utilisable
(référence stable). Parallèle exact avec `matricule` (id stable) vs `member_key`.

Conséquences : « il faut **les deux clés** pour corréler » (dictionnaire vs
usages) ; intégrité référentielle **au client** ; le schéma gagne une dimension
**`key_class`** (`epoch(group_id, key_class, n, …)`, chaque blob enregistre
`(key_class, epoch)`) ; l'**AAD** doit lier la classe de clé.

### Plusieurs GK sur une même colonne — trois sens

Une colonne chiffrée n'a pas « une clé » : chaque *valeur* référence la sienne
(préfixe `key_id`/`(key_class, epoch)`).

1. **Lignes sous GK différentes** — trivial, **déjà le cas** (deux époques = deux
   GK dans la même colonne `payload`).
2. **Même valeur chiffrée N fois** (multi-wrap au niveau champ) pour audiences
   disjointes — coût ×N stockage.
3. **Recommandé — hybride par champ** : valeur chiffrée **une fois** sous une CEK,
   CEK **wrappée sous chaque GK** autorisée. Un payload, N petits wraps ; ajouter
   un lecteur / tourner = refaire un wrap. (C'est notre modèle note généralisé.)

Nuance : le multi-wrap donne le **même** clair à tous. Pour des **vues
différentes** par clé (redaction), il faut chiffrer des **projections distinctes**
sous des clés distinctes.

---

## 6. Les deux plans de migration

| Plan | Qui | Outil | Ce qu'on peut faire |
|---|---|---|---|
| **Schéma** | serveur | **Alembic** | `ADD/DROP/RENAME COLUMN`, index sur métadonnées claires, contraintes. **Jamais** transformer un champ chiffré. |
| **Format des données chiffrées** | **client** (a les clés) | octet `v` + **upcasting** / re-seal | changer le clair, l'AEAD, l'AAD, ajouter un champ… |

Une évolution de **contenu chiffré** n'est **jamais** une migration SQL : le
serveur n'a pas les clés. C'est un **backfill client** (lazy à la lecture, ou une
passe de re-seal — rôle naturel du **CLI hors ligne du lot 0**). Le serveur peut
seulement **coordonner** via l'octet `v` visible (publier une version cible,
refuser en 409 une écriture périmée, garantir « remplace si `v == attendu` »).

Exemple type (**blind index**, lot 4) : Alembic `ADD COLUMN title_bi bytea`
(structurel) → **backfill client** qui a la GK et calcule le HMAC.

---

## 7. Ce qui fuit, même bien fait

Cacher les valeurs et le graphe ne cache pas tout. Restent visibles :
**cardinalités** des tables, **ordre/horodatage** de création, **auteur** (si
`author_id` clair), **tailles** de blobs (→ **padding**), et tout **jeton** ajouté
pour le serveur (fuite d'égalité/fréquence). À énoncer dans le modèle de menace,
pas à découvrir après coup.

---

## Annexe — Prior art (références indicatives)

Projets qui démontrent ces techniques. *Liens et état des dépôts non vérifiés
ici ; certains sont des prototypes de recherche ou archivés.*

| Projet | Ce qu'il montre |
|---|---|
| **ZeroDB** | Base E2EE, requêtes/traversée de **références chiffrées** côté client (le plus proche de ce projet ; archivé). |
| **CryptDB** (MIT) | SQL sur données chiffrées, joins via chiffrement ajustable (« onions »). Référence académique. |
| **Tahoe-LAFS** / *cryptree* | Système de fichiers E2EE à **capacités chiffrées** (read/write-caps) : suivre des liens chiffrés par étapes. |
| **Standard Notes**, **Bitwarden** | **Hiérarchie de clés** (items-keys / org-keys qui wrappent des clés d'item) : multi-clés et wrapping. |
| **Signal – Private Group System**, **Matrix / Megolm** | Appartenance chiffrée & rotation de clés de groupe (analogues de notre chaîne + époques). |
| **Cossack Labs Acra**, **CipherStash**, **MongoDB Queryable Encryption / CSFLE** | Côté requête : blind index, chiffrement déterministe, tokenisation. |
| **Peergos**, **EteSync** | Apps E2EE à données structurées / graphe chiffré. |
