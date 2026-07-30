# Démo E2EE par groupes

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
| 1 | FastAPI + Postgres, auth par défi Ed25519 | à venir |
| 2 | SvelteKit, module `crypto/`, écrans | à venir |
| 3 | Politique : quorum M-of-N, rotation de clé | à venir |
| 4 | Optionnel : blind index, note multi-groupes | à venir |

## Démarrage (lot 0)

    pip install -r lot0/requirements.txt
    python -m lot0.demo

Les 7 vérifications de la SPEC §11 s'exécutent comme assertions. Détails dans
[`lot0/README.md`](lot0/README.md).
