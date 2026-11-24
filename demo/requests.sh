#!/usr/bin/env bash
# Showcase calls against a running openverdict started with the demo profile:
#   docker compose --env-file deploy/compose/demo.env up -d --build
#   CLIENT_KEY=$(docker compose exec api openverdict create-key --name demo-client --role client)
#   ANALYST_KEY=$(docker compose exec api openverdict create-key --name demo-analyst --role analyst)
#   CLIENT_KEY=... ANALYST_KEY=... demo/requests.sh
set -euo pipefail

BASE=${BASE:-http://127.0.0.1:8000}
: "${CLIENT_KEY:?set CLIENT_KEY}" "${ANALYST_KEY:?set ANALYST_KEY}"
LISTED="http://malware-drop.test/payload.exe"

# The body goes on stdin: a 5,000-URL body is larger than one shell argument may be (128 KiB).
post() {
  printf '%s' "$3" | curl -sS -X POST "$BASE$1" -H "X-API-Key: $2" \
    -H 'Content-Type: application/json' --data-binary @-
}

summary() {
  python3 -c '
import json, sys
for r in json.load(sys.stdin)["results"]:
    why = r["reasons"][0]["detail"] if r["reasons"] else (r["error"] or "no evidence")
    print("  %-11s %-40s %s" % (r["verdict"] or "error", r["url"], why))
'
}

echo "== 1. Check eight URLs (one request, verdict + first reason each)"
post /v1/url-checks "$CLIENT_KEY" '{"urls": [
  "http://malware-drop.test/payload.exe",
  "http://secure-login.test/verify",
  "http://bad-host.test/other",
  "http://login.phish-domain.test/",
  "http://paypa1.test/login",
  "https://www.example.com/",
  "http://unlisted.test/",
  "ftp://files.test/x"]}' | summary

echo
echo "== 2. More than 100 URLs in a sync request is rejected"
too_many=$(python3 -c 'import json; print(json.dumps({"urls": ["http://a.test/"] * 101}))')
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/v1/url-checks" \
  -H "X-API-Key: $CLIENT_KEY" -H 'Content-Type: application/json' -d "$too_many")
echo "  HTTP $code"

echo
echo "== 3. Analyst marks the listed URL safe (false positive), then re-check"
override=$(post /v1/overrides "$ANALYST_KEY" \
  "{\"target_type\": \"url\", \"target\": \"$LISTED\", \"verdict\": \"safe\", \"note\": \"vendor file\"}")
echo "$override" | python3 -c 'import json,sys; o=json.load(sys.stdin); print("  override #%s: engine said %s, outcome %s" % (o["id"], o["engine_verdict"], o["outcome"]))'
post /v1/url-checks "$CLIENT_KEY" "{\"urls\": [\"$LISTED\"]}" | summary

echo
echo "== 4. Async job with 5,000 URLs"
job_body=$(python3 -c '
import json
urls = [f"http://bulk-{i}.test/" for i in range(5000)]
urls[42] = "http://secure-login.test/verify"
print(json.dumps({"urls": urls}))')
job_id=$(post /v1/jobs "$CLIENT_KEY" "$job_body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')
echo "  job $job_id"
while :; do
  job=$(curl -sS "$BASE/v1/jobs/$job_id?limit=1000" -H "X-API-Key: $CLIENT_KEY")
  status=$(echo "$job" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(j["status"], j["progress"]["done"], j["progress"]["total"])')
  echo "  $status"
  case "$status" in done*|failed*) break ;; esac
  sleep 1
done
echo "$job" | python3 -c '
import collections, json, sys
counts = collections.Counter(r["verdict"] for r in json.load(sys.stdin)["results"])
print("  first page verdicts:", dict(counts))'

echo
echo "== 5. Clean up the demo override so the next run starts fresh"
override_id=$(echo "$override" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -sS -o /dev/null -w '  DELETE override -> HTTP %{http_code}\n' -X DELETE \
  "$BASE/v1/overrides/$override_id" -H "X-API-Key: $ANALYST_KEY"
