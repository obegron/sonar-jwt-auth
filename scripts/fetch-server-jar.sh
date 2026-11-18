#!/usr/bin/env bash
# Extracts the SonarQube server jar from the image into .build/ (compile-time dependency only; never packaged).
set -euo pipefail
IMAGE=${1:-sonarqube:26.10.0.133078-community}
cd "$(dirname "$0")/.."; mkdir -p .build
c=$(docker create "$IMAGE"); trap 'docker rm "$c" >/dev/null' EXIT
jar=$(docker run --rm --entrypoint sh "$IMAGE" -c 'ls /opt/sonarqube/lib/sonar-application-*.jar')
docker cp "$c:$jar" .build/sonar-application.jar
echo "extracted $jar -> .build/sonar-application.jar"
