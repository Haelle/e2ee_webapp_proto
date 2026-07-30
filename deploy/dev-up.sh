#!/usr/bin/env sh
# Monte la pile de dev via Podman (ou kubectl) avec rechargement à chaud.
# Requiert : podman >= 4 (kube play). Fallback documenté : kubectl.
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
K8S="$REPO_ROOT/deploy/k8s"
RENDERED="$K8S/dev-stack.rendered.yaml"

echo ">> rendu du manifeste (REPO_ROOT=$REPO_ROOT)"
sed "s#__REPO_ROOT__#$REPO_ROOT#g" "$K8S/dev-stack.yaml" > "$RENDERED"

echo ">> construction des images de dev"
podman build -t e2ee-server:dev -f "$REPO_ROOT/server/Containerfile" "$REPO_ROOT/server"
podman build -t e2ee-web:dev    -f "$REPO_ROOT/web/Containerfile"    "$REPO_ROOT/web"

echo ">> podman kube play"
podman kube play "$RENDERED"

cat <<'EOF'

Pile lancée. Accès :
  - front  : http://localhost:30173   (Vite, HMR)
  - api    : http://localhost:8000     (port-forward si besoin : voir README)
  - pg     : postgres:5432 dans le réseau du pod

Édite le code sur l'hôte → rechargement automatique.
Arrêt : deploy/dev-down.sh
EOF
