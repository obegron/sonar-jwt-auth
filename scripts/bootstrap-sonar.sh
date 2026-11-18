#!/usr/bin/env bash
# Idempotent-ish bootstrap of a fresh SonarQube: admin pw, service user/group, analysis token -> stdout path
set -euo pipefail
S=${S:-http://localhost:9000}; PW=${PW:-Admin-spike-123!}; SVC=${SVC:-Svc-spike-123!}
for i in $(seq 1 120); do curl -sf $S/api/system/status | grep -q '"UP"' && break; sleep 5; [ $i -eq 120 ] && { echo "SonarQube at $S did not come up" >&2; exit 1; }; done
curl -s -u admin:admin -X POST $S/api/users/change_password -d login=admin -d previousPassword=admin -d password="$PW" >/dev/null || true
A="-u admin:$PW"
curl -s $A -X POST $S/api/user_groups/create -d name=tekton-scanners >/dev/null
for p in provisioning scan; do curl -s $A -X POST $S/api/permissions/add_group -d groupName=tekton-scanners -d permission=$p >/dev/null; done
curl -s $A -X POST $S/api/users/create -d login=tekton-svc -d name='Tekton Scanner' -d password="$SVC" >/dev/null
curl -s $A -X POST $S/api/user_groups/add_user -d name=tekton-scanners -d login=tekton-svc >/dev/null
curl -s -u "tekton-svc:$SVC" -X POST $S/api/user_tokens/generate -d name=spike -d type=GLOBAL_ANALYSIS_TOKEN | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])'
