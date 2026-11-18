#!/usr/bin/env bash
# Runs Maven and retries ONLY when the failure is dependency resolution (Maven Central intermittently answers "not found"/timeouts for artifacts that exist).
# A real build or test failure fails immediately. Usage: scripts/mvn-retry.sh <maven args>
set -uo pipefail
attempts=${MVN_RETRY_ATTEMPTS:-4}; log=$(mktemp)
for i in $(seq 1 "$attempts"); do
  mvn "$@" 2>&1 | tee "$log"; rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] && exit 0
  if grep -qE 'Could not find artifact|Could not transfer artifact|PluginResolutionException|DependencyResolutionException|Connection reset|Read timed out|Connect timed out' "$log" && [ "$i" -lt "$attempts" ]; then
    echo ">>> dependency resolution failed (attempt $i/$attempts), retrying in $((i * 20))s"; sleep $((i * 20)); continue
  fi
  exit "$rc"
done
