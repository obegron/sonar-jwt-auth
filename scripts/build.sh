#!/usr/bin/env bash
# One-shot build: fetch the compile-time server jar (needs docker), run tests, package.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .build/sonar-application.jar ] || scripts/fetch-server-jar.sh "${1:-sonarqube:26.10.0.133078-community}"
mvn -B verify
ls -1 target/sonar-jwt-auth-*.jar
