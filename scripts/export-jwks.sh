#!/usr/bin/env bash
# Export a Kubernetes cluster's service-account signing keys, for a source with "jwksFile":
#   scripts/export-jwks.sh <kube-context> > jenkins-jwks.json
# Keys only change when the cluster's service-account signing key is rotated: re-export then (or run this from a CronJob).
set -euo pipefail
kubectl ${1:+--context "$1"} get --raw /openid/v1/jwks
