#!/usr/bin/env bash
# Kubernetes end-to-end test: the OFFICIAL SonarQube Helm chart + deploy/helm/values-sonar-jwt-auth.yaml (init container, agent, ConfigMap
# directory mount) in a throw-away k3d cluster, key source "Kubernetes API server" (CA + ServiceAccount token), and a scanner pod whose only
# credential is its projected ServiceAccount token. Needs docker, k3d, helm, kubectl and a built jar (mvn package).
set -uo pipefail
cd "$(dirname "$0")/.."
CLUSTER=${CLUSTER:-sjat-e2e}; NS=sonarqube; PF_PORT=${PF_PORT:-19001}
JAR=$(ls target/sonar-jwt-auth-*.jar | grep -v sources | head -1); [ -f "$JAR" ] || { echo "build first: mvn package"; exit 2; }
pass=0; fail=0; PF_PID=""
check(){ if [ "$2" = "$3" ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1 (expected $3, got $2)"; fail=$((fail+1)); fi; }
W=$(mktemp -d)
cleanup(){ [ -n "$PF_PID" ] && kill $PF_PID 2>/dev/null; if [ "$fail" -gt 0 ] || [ "${DEBUG:-}" = 1 ]; then
    echo "=== diagnostics ==="; kubectl -n $NS get pods -o wide 2>&1 | head
    echo "--- pod status:"; kubectl -n $NS get pod sonarqube-sonarqube-0 -o jsonpath='{.status.phase} {.status.reason} {.status.message}{"\n"}{range .status.initContainerStatuses[*]}init {.name}: {.state}{"\n"}{end}{range .status.containerStatuses[*]}{.name}: {.state} last={.lastState}{"\n"}{end}' 2>&1 | cut -c1-400
    echo "--- events:"; kubectl -n $NS get events --sort-by=.lastTimestamp 2>&1 | tail -20 | cut -c1-300
    echo "--- node:"; kubectl describe node 2>&1 | grep -E 'Conditions|MemoryPressure|DiskPressure|PIDPressure|ephemeral|memory ' | head -12
    for c in install-sonar-jwt-auth sonarqube; do echo "--- logs $c:"; kubectl -n $NS logs sonarqube-sonarqube-0 -c $c 2>&1 | tail -12 | cut -c1-250; echo "--- previous logs $c:"; kubectl -n $NS logs sonarqube-sonarqube-0 -c $c --previous 2>&1 | grep -E 'jwt-auth|ERROR|Caused|Exception' | tail -8 | cut -c1-250; done
  fi
  [ "${KEEP:-}" = 1 ] || k3d cluster delete $CLUSTER >/dev/null 2>&1; rm -rf "$W"; }
trap cleanup EXIT

cp "$JAR" docker/sonar-jwt-auth.jar
docker build -q -t sonar-jwt-auth-init:e2e -f docker/Dockerfile.init docker >/dev/null || exit 2
docker image inspect sonarsource/sonar-scanner-cli >/dev/null 2>&1 || docker pull -q sonarsource/sonar-scanner-cli >/dev/null
k3d cluster delete $CLUSTER >/dev/null 2>&1; k3d cluster create $CLUSTER --wait >/dev/null || exit 2
k3d image import sonar-jwt-auth-init:e2e sonarsource/sonar-scanner-cli -c $CLUSTER >/dev/null 2>&1

helm repo add sonarqube https://SonarSource.github.io/helm-chart-sonarqube >/dev/null 2>&1; helm repo update >/dev/null 2>&1
kubectl create namespace $NS >/dev/null
kubectl -n $NS create configmap sonar-jwt-auth-config --from-file=jwt-auth.json=deploy/jwt-auth-config.k8s-e2e.json >/dev/null
sed 's#ghcr.io/obegron/sonar-jwt-auth-init:[0-9.]*#sonar-jwt-auth-init:e2e#' deploy/helm/values-sonar-jwt-auth.yaml > "$W/values.yaml"
echo "helm install (official chart, embedded H2: test only)..."
helm install sonarqube sonarqube/sonarqube -n $NS -f "$W/values.yaml" --set monitoringPasscode=e2e-passcode \
  --set initSysctl.enabled=false --set initFs.enabled=false --set 'sonarProperties.sonar\.es\.bootstrap\.checks\.disable=true' \
  --set resources.requests.memory=1500Mi --set resources.requests.cpu=300m --set resources.limits.memory=4Gi --set persistence.enabled=false \
  --wait --timeout 15m >"$W/helm.log" 2>&1
helm_rc=$?
check "helm install succeeds" "$helm_rc" 0
if [ $helm_rc -ne 0 ]; then echo "--- helm output:"; tail -15 "$W/helm.log"; exit 1; fi   # nothing else can work: stop, the trap prints diagnostics

kubectl -n $NS port-forward svc/sonarqube-sonarqube $PF_PORT:9000 >/dev/null 2>&1 & PF_PID=$!
S=http://localhost:$PF_PORT
for i in $(seq 1 60); do curl -sf $S/api/system/status 2>/dev/null | grep -q '"UP"' && break; sleep 5; done
check "SonarQube is UP" "$(curl -s $S/api/system/status | grep -c '"UP"')" 1
S=$S PW='Admin-it-123!' scripts/bootstrap-sonar.sh >/dev/null
ADMIN=(-u 'admin:Admin-it-123!')

echo "boot log:"
LOGS=$(kubectl -n $NS logs sonarqube-sonarqube-0 2>&1)
check "agent registered" "$([ "$(echo "$LOGS" | grep -c 'jwt-auth: extension registered')" -ge 1 ] && echo yes)" yes
check "config loaded from the mounted ConfigMap" "$(echo "$LOGS" | grep -c 'jwt-auth: loaded 1 source(s) from /opt/sonarqube/jwt-auth/jwt-auth.json')" 1
check "keys read from the Kubernetes API server (CA + SA token)" "$(echo "$LOGS" | grep -c "source 'k8s': loaded [1-9] signing key")" 1

scan(){ kubectl delete pod scanner-e2e --ignore-not-found --wait >/dev/null
  sed "s#value: \"http://sonarqube.default.svc:9000\"#value: \"http://sonarqube-sonarqube.$NS.svc:9000\"#; s#value: e2e-from-pod#value: $1#" deploy/scanner-job.yaml | kubectl apply -f - >/dev/null
  kubectl wait --for=jsonpath='{.status.phase}'=Succeeded pod/scanner-e2e --timeout=240s >/dev/null 2>&1
  kubectl logs scanner-e2e 2>&1 | grep -c 'EXECUTION SUCCESS'; }
echo "scanner pod (namespace default, only credential: projected ServiceAccount token):"
check "scan of project default-app (own namespace prefix) succeeds" "$(scan default-app)" 1
check "scan of project other-app (another team's prefix) is refused" "$(scan other-app)" 0
sleep 5
check "analysis was accepted and finished" "$(curl -s "${ADMIN[@]}" "$S/api/ce/activity?component=default-app&ps=1" | python3 -c 'import sys,json;t=json.load(sys.stdin)["tasks"];print(t[0]["status"] if t else "none")')" SUCCESS
check "user was auto-provisioned as external user" "$(curl -s "${ADMIN[@]}" "$S/api/users/search?q=k8s&ps=20" | python3 -c 'import sys,json;print(sorted({u.get("externalProvider") for u in json.load(sys.stdin)["users"]}))' )" "['jwt-auth']"
check "project of the other prefix was never created" "$(curl -s "${ADMIN[@]}" "$S/api/projects/search?projects=other-app" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["components"]))')" 0

echo; echo "passed: $pass  failed: $fail"; [ $fail -eq 0 ]
