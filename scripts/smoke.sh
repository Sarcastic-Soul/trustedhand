#!/usr/bin/env bash
# Smoke test: start a demo household, then ask for the bill list.
# Usage: scripts/smoke.sh   (reads api_url and chat_url from terraform output)
set -euo pipefail
cd "$(dirname "$0")/.."
API=$(terraform -chdir=infra output -raw api_url)
CHAT=$(terraform -chdir=infra output -raw chat_url)

START=$(curl -sS -X POST "$API/demo/start" -H 'content-type: application/json' -d '{}')
echo "start: $START" | sed -E 's/"chat_token": ?"[^"]+"/"chat_token":"<hidden>"/'
TOKEN=$(printf '%s' "$START" | python3 -c 'import json,sys; print(json.load(sys.stdin)["chat_token"])')

BODY=$(TOKEN="$TOKEN" python3 -c 'import json,os; print(json.dumps({"chat_token": os.environ["TOKEN"], "message": "List my bills"}))')
echo "chat:"
curl -sS -X POST "$CHAT" -H 'content-type: application/json' -d "$BODY" | python3 -m json.tool
