# Lot 0 — modèle E2EE par groupes, hors ligne

Première étape de la [SPEC](../SPEC.md). Objectif : **valider le modèle de
chiffrement avant toute plomberie web** (SPEC §12). Aucun réseau, stockage
SQLite, trois+ membres simulés dont les clés ne vivent que le temps du process.

Ce lot est aussi l'**outil de secours** mentionné au test §11.7 : il déchiffre
un dump de base sans le serveur.

## Ce qui est prouvé

Les quatre propriétés de la SPEC §1, sous forme d'assertions exécutables :

1. Le serveur ne peut pas lire le contenu des notes — un dump ne contient aucun
   clair.
2. Un membre coopté accède au groupe sans qu'aucune note ne soit retouchée.
3. La composition est reconstruite par **rejeu de la chaîne signée**, jamais lue
   dans une table.
4. Un changement d'époque coupe les écritures futures sans rechiffrer le passé.

## Structure

| Fichier | Rôle |
|---|---|
| `model.py` | Toute la crypto **et** l'autorité (rejeu de chaîne). Les 4 fonctions à secret de §9 : `unlock_keyblob`, `open_epoch`, `seal_note`, `open_note`. |
| `store.py` | Le « serveur » : SQLite, schéma §5, **aucune** crypto. Range des blobs. |
| `client.py` | Le client membre : orchestre les flux §10 (enrôlement, genèse, écriture, cooptation, radiation). La composition passe toujours par `replay_chain`. |
| `recover.py` | Outil de secours hors ligne (§11.7). |
| `demo.py` | Scénario complet + les 7 vérifications de §11. |

Le point de conception clé (SPEC §4) : **`store.py` n'importe aucune
bibliothèque de chiffrement.** Si on se surprend à en ajouter une côté serveur,
c'est une erreur.

## Modèle de clés (§3)

    passphrase ──déverrouille──▶ keyblob (age X25519 + Ed25519)
                                    │ ouvre
                                    ▼
                                  GK (1 par groupe et par époque)
                                    │ wrappe
                                    ▼
                                  CEK (1 par note) ──▶ payload AEAD

`unlock_keyblob` est le **seul** point que la carte à puce remplacera ; les
trois autres niveaux ne bougent pas (tout l'intérêt du keyblob intermédiaire).

## Installation & exécution

    pip install -r lot0/requirements.txt          # pyrage, pynacl, cbor2

    python -m lot0.demo                            # scénario + vérifications §11

    # secours : déchiffre un dump sans le serveur
    python -m lot0.recover <db.sqlite> <matricule> <passphrase> <groupe>

## Correspondance avec les vérifications §11

| Test | Où |
|---|---|
| 1. dump sans clair | `demo.c1` + `sqlite3 … .dump \| grep` |
| 2. époque n ne lit pas n+1 | `demo.c2` |
| 3. échange de payload en SQL → AAD | `demo.c3` |
| 4. déclaration de non-membre rejetée au rejeu | `demo.c4` (le plus important : l'autorité est côté client) |
| 5. stmt modifié → chaîne cassée | `demo.c5` |
| 6. historique lisible ssi rewrappé | `demo.c6` |
| 7. secours hors ligne | `demo.c7` + `recover.py` |

## Choix notables

- **Une enveloppe `age` par époque**, pas une par membre : coopter = réécrire
  cette ligne avec un destinataire de plus.
- **On signe et on stocke les mêmes octets CBOR** : jamais de réencodage, donc
  pas de question de sérialisation canonique (§7, §13).
- L'enveloppe d'une époque étant réécrite en place à la cooption, seule la
  **dernière** déclaration visant une époque pinne l'enveloppe stockée (`env`) ;
  les précédentes restent couvertes par la signature et le chaînage `prev`.
- Nonce XChaCha20 **aléatoire** (24 octets), jamais de compteur (§13).
- Chaque blob porte un champ de version `v` dès le premier octet (§13).

## Hors périmètre (accroches en place)

`checkPolicy` est déjà un paramètre de `replay_chain` (quorum M-of-N, lot 3).
Le déverrouillage du keyblob est isolé dans `unlock_keyblob` (carte, plus tard).
Le reste suit dans les lots 1→4.
