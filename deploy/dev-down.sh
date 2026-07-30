#!/usr/bin/env sh
# Arrête et nettoie la pile de dev.
set -eu
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RENDERED="$REPO_ROOT/deploy/k8s/dev-stack.rendered.yaml"
[ -f "$RENDERED" ] && podman kube down "$RENDERED" || echo "rien à arrêter (manifeste non rendu)"
