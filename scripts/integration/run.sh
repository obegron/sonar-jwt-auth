#!/usr/bin/env bash
# End-to-end test against a real SonarQube container: JWT happy path, rejection cases, scope/path attacks, concurrent first use,
# hot reload. DB=postgres runs SonarQube against an external PostgreSQL instead of the embedded H2. Needs docker, python3 + `cryptography`, curl, and a built jar (mvn package). Usage: scripts/integration/run.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
SONAR_IMAGE=${SONAR_IMAGE:-sonarqube:26.10.0.133078-community}
PORT=${SONAR_PORT:-19000}; JWKS_PORT=${JWKS_PORT:-18765}; NAME=sjat-sonarqube
ISS=https://issuer.test.invalid
W=$(mktemp -d); trap 'docker rm -f $NAME sjat-pg >/dev/null 2>&1; docker network rm sjat-net >/dev/null 2>&1; kill $JWKS_PID 2>/dev/null; rm -rf "$W"' EXIT
JAR=$(ls target/sonar-jwt-auth-*.jar | grep -v sources | head -1); [ -f "$JAR" ] || { echo "build first: mvn package"; exit 2; }
S=http://localhost:$PORT; ADMIN=(-u 'admin:Admin-it-123!')
pass=0; fail=0
check(){ if [ "$2" = "$3" ]; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FAIL $1 (expected $3, got $2)"; fail=$((fail+1)); fi; }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
mint(){ python3 scripts/integration/jwt_tool.py mint "$W" $ISS "$@"; }

python3 scripts/integration/jwt_tool.py gen "$W"
python3 scripts/integration/jwt_tool.py serve "$W" $JWKS_PORT $ISS & JWKS_PID=$!
mkdir -p "$W/cfg" docker/.it && cp "$JAR" docker/.it/sonar-jwt-auth.jar
cat > "$W/cfg/jwt-auth.json" <<JSON
{"sources":[{"name":"it","issuer":"$ISS","discoveryUrl":"http://host.docker.internal:$JWKS_PORT","allowInsecureHttp":true,"audiences":["sonarqube"],
 "rules":[{"subject":"system:serviceaccount:(?<ns>[a-z0-9-]+):(?<sa>[a-z0-9-]+)","login":"it_\${ns}_\${sa}","name":"it \${ns}/\${sa}",
           "autoProvision":true,"groups":["tekton-scanners"],"projectKeyPattern":"tekton-.*"}]}]}
JSON
python3 scripts/integration/jwt_tool.py jwks "$W" > "$W/cfg/file-jwks.json"
python3 - "$W/cfg/jwt-auth.json" <<'PY'
import json,sys
p=sys.argv[1]; c=json.load(open(p))
# many namespaces, one rule: every appN namespace gets its own user and its own project-key prefix
c["sources"][0]["rules"].insert(0,{"subject":"system:serviceaccount:(?<ns>app[0-9]+):pipeline","login":"ns_${ns}","name":"Tekton ${ns}","autoProvision":True,
  "groups":["tekton-scanners"],"projectKeyPattern":"${ns}_.*"})
c["sources"][0]["rules"].insert(1,{"subject":"system:serviceaccount:(?<ns>team|team-dev):pipeline","login":"ns_${ns}","name":"Team ${ns}","autoProvision":True,
  "groups":["tekton-scanners"],"projectKeyPattern":"${ns}_.*"})
# a Jenkins-like source that is deliberately NOT project-prefixed: every project key is fine, paths are still limited to the scanner's
c["sources"].append({"name":"jenkinsish","issuer":"https://jenkins.test.invalid","jwksFile":"/opt/sonarqube/jwt-auth/file-jwks.json","audiences":["sonarqube"],
  "rules":[{"subject":".*","login":"jenkins_ci","name":"Jenkins CI","autoProvision":True,"groups":["tekton-scanners"],"projectKeyPattern":".*"}]})
c["sources"].append({"name":"filesrc","allowQualityGateWait":False,"issuer":"https://file.test.invalid","jwksFile":"/opt/sonarqube/jwt-auth/file-jwks.json","audiences":["sonarqube"],
  "rules":[{"subject":"system:serviceaccount:(?<ns>[a-z0-9-]+):(?<sa>[a-z0-9-]+)","login":"file_${ns}_${sa}","autoProvision":True,"groups":["tekton-scanners"],"projectKeyPattern":"file-.*"}]})
json.dump(c,open(p,"w"))
PY
chmod -R a+rX "$W/cfg"
docker build -q --build-arg SONAR_IMAGE=$SONAR_IMAGE -t sjat-sonarqube:it -f docker/Dockerfile docker/.it >/dev/null || exit 2
DBARGS=()
if [ "${DB:-h2}" = postgres ]; then
  docker network create sjat-net >/dev/null 2>&1
  docker run -d --name sjat-pg --network sjat-net --tmpfs /var/lib/postgresql/data -e POSTGRES_USER=sonar -e POSTGRES_PASSWORD=sonar -e POSTGRES_DB=sonar postgres:17-alpine >/dev/null || exit 2
  for i in $(seq 1 30); do docker exec sjat-pg pg_isready -U sonar >/dev/null 2>&1 && break; sleep 2; done
  DBARGS=(--network sjat-net -e SONAR_JDBC_URL=jdbc:postgresql://sjat-pg:5432/sonar -e SONAR_JDBC_USERNAME=sonar -e SONAR_JDBC_PASSWORD=sonar)
  echo "database: external PostgreSQL"
fi
docker run -d --name $NAME "${DBARGS[@]}" --add-host=host.docker.internal:host-gateway -p $PORT:9000 \
  --tmpfs /opt/sonarqube/data:uid=1000,gid=1000,size=2g --tmpfs /opt/sonarqube/temp:uid=1000,gid=1000,size=1g -v "$W/cfg":/opt/sonarqube/jwt-auth:ro \
  -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true sjat-sonarqube:it >/dev/null
echo "waiting for SonarQube..."; until curl -sf $S/api/system/status | grep -q '"UP"'; do sleep 5; done
S=$S PW='Admin-it-123!' scripts/bootstrap-sonar.sh >/dev/null

echo "boot log:"; docker logs $NAME 2>&1 | grep -E 'jwt-auth' | cut -c1-200 | head -4
echo "authentication:"
OK=$(mint --sub system:serviceaccount:ci:builder)
check "no credentials -> 401"                           "$(code $S/api/users/current)" 401
check "valid JWT can create an in-scope project"        "$(code -X POST -H "Authorization: Bearer $OK" $S/api/projects/create -d name=a -d project=tekton-a)" 200
check "expired JWT -> 401"                              "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:ci:builder --age 7200 --ttl 60)" $S/api/projects/create -d name=b -d project=tekton-b)" 401
check "wrong audience -> 401"                           "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:ci:builder --aud other)" $S/api/projects/create -d name=b -d project=tekton-b)" 401
check "unknown signing key id -> 401"                   "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:ci:builder --kid nope)" $S/api/projects/create -d name=b -d project=tekton-b)" 401
check "token valid for 10 days -> 401"                  "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:ci:builder --ttl 864000)" $S/api/projects/create -d name=b -d project=tekton-b)" 401
check "project outside scope is refused (401)"      "$(code -X POST -H "Authorization: Bearer $OK" $S/api/projects/create -d name=x -d project=other-x)" 401
check "ce/submit naming no project is refused (fail closed)" "$(code -X POST -H "Authorization: Bearer $OK" $S/api/ce/submit)" 401
check "endpoint outside the allowlist -> 401"           "$(code -H "Authorization: Bearer $OK" $S/api/users/search)" 401
check "token minting endpoint is not reachable"         "$(code -X POST -H "Authorization: Bearer $OK" $S/api/user_tokens/generate -d name=x)" 401
for evil in '/api/ce/submit/../../api/users/search' '/api/ce/submit;x=1/../users/search' '/api/ce/%2e%2e/users/search' '/api//users/search'; do
  check "path trick $evil not served" "$([ "$(code --path-as-is -H "Authorization: Bearer $OK" "$S$evil")" != 200 ] && echo refused)" refused
done
FILE_TOK=$(python3 scripts/integration/jwt_tool.py mint "$W" https://file.test.invalid --sub system:serviceaccount:ci:filer)
check "second source (static jwksFile, no network) works"  "$(code -X POST -H "Authorization: Bearer $FILE_TOK" $S/api/projects/create -d name=f -d project=file-a)" 200
check "...and is scoped by its own projectKeyPattern"        "$(code -X POST -H "Authorization: Bearer $FILE_TOK" $S/api/projects/create -d name=f -d project=tekton-z)" 401
check "...and its tokens do not work for the other source's scope" "$(code -X POST -H "Authorization: Bearer $OK" $S/api/projects/create -d name=f -d project=file-b)" 401
FILE_TOK=$(python3 scripts/integration/jwt_tool.py mint "$W" https://file.test.invalid --sub system:serviceaccount:ci:filer)
echo "scanner scenarios with the default allowlist (project tekton-scan2):"
scanrun(){ docker run --rm --network host --add-host=host.docker.internal:host-gateway -v "$W/src":/usr/src -e SONAR_HOST_URL=$S -e SONAR_TOKEN="$(mint --sub system:serviceaccount:ci:builder)" \
  sonarsource/sonar-scanner-cli "$@" 2>&1; }
refused(){ docker logs $NAME 2>&1 | grep -E 'jwt-auth: .*(may not call|denied on)' | sed -E 's/^.*jwt-auth: //' | sort | uniq -c | cut -c1-200; }
OUT=$(scanrun -Dsonar.projectKey=tekton-scan2); check "first analysis succeeds" "$(echo "$OUT" | grep -c 'EXECUTION SUCCESS')" 1
OUT=$(scanrun -Dsonar.projectKey=tekton-scan2); check "second analysis of the existing project succeeds" "$(echo "$OUT" | grep -c 'EXECUTION SUCCESS')" 1
[ "$(echo "$OUT" | grep -c 'EXECUTION SUCCESS')" = 1 ] || { echo "--- refused by the extension:"; refused; }
OUT=$(scanrun -Dsonar.projectKey=tekton-scan2 -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=120); check "analysis with sonar.qualitygate.wait=true succeeds" "$(echo "$OUT" | grep -c 'EXECUTION SUCCESS')" 1
[ "$(echo "$OUT" | grep -c 'EXECUTION SUCCESS')" = 1 ] || { echo "--- refused by the extension:"; refused; echo "$OUT" | grep -E 'ERROR|WARN' | head -4 | cut -c1-200; }
check "quality-gate polling is refused for a source that switched it off" "$(code -H "Authorization: Bearer $FILE_TOK" "$S/api/ce/task?id=nope")" 401
check "...and reaches SonarQube (404 task not found) by default"  "$(code -H "Authorization: Bearer $(mint --sub system:serviceaccount:ci:builder)" "$S/api/ce/task?id=nope")" 404
echo "all calls refused so far (only the deliberate refusals above are expected):"; refused

echo "many namespaces, one rule (app1/app2/app3):"
for n in app1 app2 app3; do
  T=$(mint --sub system:serviceaccount:$n:pipeline)
  check "$n can create its own project (${n}_web)" "$(code -X POST -H "Authorization: Bearer $T" $S/api/projects/create -d name=w -d project=${n}_web)" 200
done
T1=$(mint --sub system:serviceaccount:app1:pipeline)
check "app1 cannot touch app2's projects"        "$(code -X POST -H "Authorization: Bearer $T1" $S/api/projects/create -d name=w -d project=app2_api)" 401
check "app1 cannot touch an unprefixed project"  "$(code -X POST -H "Authorization: Bearer $T1" $S/api/projects/create -d name=w -d project=web)" 401
check "a namespace outside the rule (app1x) is refused" "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:app1x:pipeline)" $S/api/projects/create -d name=w -d project=app1x_web)" 401
check "a different ServiceAccount in app1 is refused"   "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:app1:other)" $S/api/projects/create -d name=w -d project=app1_x)" 401
TA=$(mint --sub system:serviceaccount:team:pipeline); TD=$(mint --sub system:serviceaccount:team-dev:pipeline)
check "namespace 'team' can create team_a"                   "$(code -X POST -H "Authorization: Bearer $TA" $S/api/projects/create -d name=w -d project=team_a)" 200
check "namespace 'team' cannot touch 'team-dev' projects"    "$(code -X POST -H "Authorization: Bearer $TA" $S/api/projects/create -d name=w -d project=team-dev_a)" 401
check "namespace 'team-dev' can create team-dev_a"           "$(code -X POST -H "Authorization: Bearer $TD" $S/api/projects/create -d name=w -d project=team-dev_a)" 200
check "three namespaces -> three distinct users" "$(curl -s "${ADMIN[@]}" "$S/api/users/search?q=Tekton+app&ps=20" | python3 -c 'import sys,json;print(len([u for u in json.load(sys.stdin)["users"] if u.get("externalProvider")=="jwt-auth"]))')" 3
echo "Jenkins-style source without project prefixes:"
JT=$(python3 scripts/integration/jwt_tool.py mint "$W" https://jenkins.test.invalid --sub "https://jenkins.example/job/anything")
check "any project key is allowed (payments-api)"      "$(code -X POST -H "Authorization: Bearer $JT" $S/api/projects/create -d name=p -d project=payments-api)" 200
check "any project key is allowed (Some.Other:key_1)"  "$(code -X POST -H "Authorization: Bearer $JT" $S/api/projects/create -d name=p -d project=Some.Other:key_1)" 200
check "...but still only the scanner's endpoints"      "$(code -H "Authorization: Bearer $JT" $S/api/users/search)" 401
check "...and a request naming no project is refused"  "$(code -X POST -H "Authorization: Bearer $JT" $S/api/ce/submit)" 401
check "ordinary SonarQube token still works"            "$(code -u "$(curl -s "${ADMIN[@]}" -X POST $S/api/user_tokens/generate -d name=t | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])'):" $S/api/users/current)" 200

echo "concurrent first use of a NEW identity (8 parallel requests):"
NEW=$(mint --sub system:serviceaccount:ci:fresh)
PIDS=""; for i in 1 2 3 4 5 6 7 8; do ( code -X POST -H "Authorization: Bearer $NEW" $S/api/projects/create -d name=p$i -d project=tekton-p$i > "$W/par$i"; echo >> "$W/par$i" ) & PIDS="$PIDS $!"; done; wait $PIDS
res=$(cat "$W"/par? | grep . | sort | uniq -c | tr -s ' ' | tr '\n' ';')
check "all 8 succeed" "$res" " 8 200;"
n=$(curl -s "${ADMIN[@]}" "$S/api/users/search?q=fresh" | python3 -c 'import sys,json;print(len([u for u in json.load(sys.stdin)["users"] if u.get("externalProvider")=="jwt-auth"]))')
check "exactly one user was provisioned" "$n" 1

echo "real scanner run with the JWT as SONAR_TOKEN:"
mkdir -p "$W/src" && echo 'print("hi")' > "$W/src/a.py"
docker run --rm --network host --add-host=host.docker.internal:host-gateway -v "$W/src":/usr/src -e SONAR_HOST_URL=$S -e SONAR_TOKEN="$(mint --sub system:serviceaccount:ci:builder)" \
  sonarsource/sonar-scanner-cli -Dsonar.projectKey=tekton-scan > "$W/scan.log" 2>&1
check "scanner succeeds" "$(grep -c 'EXECUTION SUCCESS' "$W/scan.log")" 1
grep -q 'EXECUTION SUCCESS' "$W/scan.log" || { echo "--- scanner output:"; grep -E 'ERROR|WARN|401|403' "$W/scan.log" | head -8; echo "--- server:"; docker logs $NAME 2>&1 | grep 'jwt-auth' | tail -6 | cut -c1-230; }
sleep 6
who2=$(curl -s "${ADMIN[@]}" "$S/api/ce/activity?component=tekton-scan&ps=1" | python3 -c 'import sys,json;t=json.load(sys.stdin)["tasks"];print(t[0]["status"] if t else "none")')
check "analysis finished successfully" "$who2" SUCCESS
sub=$(curl -s "${ADMIN[@]}" "$S/api/ce/activity?component=tekton-scan&ps=1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["tasks"][0].get("submitterLogin",""))')
check "submitter is a jwt-auth user" "$(curl -s "${ADMIN[@]}" "$S/api/users/search?q=$sub" | python3 -c 'import sys,json;print([u["externalProvider"] for u in json.load(sys.stdin)["users"] if u["login"]=="'"$sub"'"][0])')" jwt-auth

echo "hot reload (background watcher, no traffic needed):"
waitlog(){ for i in $(seq 1 15); do docker logs $NAME 2>&1 | grep -q "$1" && return 0; sleep 2; done; return 1; }
sed -i 's/"it"/"it-renamed"/' "$W/cfg/jwt-auth.json"
waitlog 'it-renamed'; check "config change is picked up without restart" "$?" 0
echo '{ broken' > "$W/cfg/jwt-auth.json"
waitlog 'INVALID config'; check "broken config is reported in the log" "$?" 0
check "and the previous config stays active" "$(code -X POST -H "Authorization: Bearer $(mint --sub system:serviceaccount:ci:builder)" $S/api/projects/create -d name=c -d project=tekton-c)" 200

echo; echo "passed: $pass  failed: $fail"; [ $fail -eq 0 ]
