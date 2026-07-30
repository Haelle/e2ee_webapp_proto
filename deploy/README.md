# Déploiement de dev — Podman + manifeste Kubernetes

Pile de développement à **rechargement à chaud**, décrite comme un manifeste
Kubernetes et jouée par **Podman** (`podman kube play`). Le même manifeste
s'applique sur un vrai cluster avec `kubectl`.

## Contenu

| Fichier | Rôle |
|---|---|
| `k8s/dev-stack.yaml` | Manifeste (gabarit) : Postgres + serveur + front, 3 `Deployment`, 3 `Service`, 1 `PVC`. `__REPO_ROOT__` y est substitué au rendu. |
| `dev-up.sh` | Rend le manifeste, construit les images de dev, `podman kube play`. |
| `dev-down.sh` | `podman kube down`. |
| `../server/Containerfile` | Image de dev du serveur (uv). |
| `../web/Containerfile` | Image de dev du front (pnpm). |
| `../.devcontainer/` | Environnement de dev complet (VS Code + Podman). |

## Rechargement à chaud

Le code source de l'hôte est **monté** dans les conteneurs (`hostPath`) :

- serveur → `uvicorn --reload` voit les modifications Python ;
- front → HMR de Vite.

Les dépendances (`.venv`, `node_modules`) vivent dans des volumes dédiés qui
**masquent** ceux de l'hôte, pour éviter les binaires natifs incompatibles entre
hôte et conteneur.

## Lancer

```sh
deploy/dev-up.sh          # build + podman kube play
# front : http://localhost:30173   api : http://localhost:8000
deploy/dev-down.sh        # arrêt + nettoyage
```

> Prérequis : `podman >= 4` (pour `kube play`). L'API est exposée dans le réseau
> du pod ; pour y accéder depuis l'hôte, soit passer par le front (proxy Vite, à
> venir au lot 2), soit `podman kube play` expose déjà le NodePort du front.

## Sur un vrai cluster

```sh
sed "s#__REPO_ROOT__#$PWD#g" deploy/k8s/dev-stack.yaml | kubectl apply -f -
```

Le montage `hostPath` suppose un nœud unique (Podman, minikube, kind avec
montage). Pour un déploiement multi-nœuds réel, remplacer les `hostPath` par des
images construites (source figée) et retirer `--reload` / `pnpm dev` — c'est un
sujet de lot ultérieur, hors périmètre de cette itération.
