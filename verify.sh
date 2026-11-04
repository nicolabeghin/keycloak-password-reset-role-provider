#!/usr/bin/env bash
#
# End-to-end verification of the password-reset role provider against the throwaway Keycloak
# started by docker-compose.yml. Creates two disposable realms with NO user federation, then
# asserts the positive and — more importantly — the negative cases.
#
#   mvn -B clean package && docker compose up -d && ./verify.sh
#
set -euo pipefail

KC="${KC:-http://localhost:18080}"
MAILPIT="${MAILPIT:-http://localhost:18025}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
REALM="${REALM:-sandbox}"
OTHER_REALM="${OTHER_REALM:-othersandbox}"
ROLE="trigger-password-reset"

pass=0
fail=0

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }

admin_token() {
  curl -sS --fail-with-body -X POST "$KC/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d username="$ADMIN_USER" -d password="$ADMIN_PASS" \
    -d grant_type=password | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
}

kc_admin() { # method path [json]
  local method=$1 path=$2 body=${3:-}
  if [ -n "$body" ]; then
    curl -sS -o /dev/null -w '%{http_code}' -X "$method" "$KC/admin$path" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body"
  else
    curl -sS -X "$method" "$KC/admin$path" -H "Authorization: Bearer $TOKEN"
  fi
}

# ---------------------------------------------------------------- wait for server
say "Waiting for Keycloak at $KC"
for _ in $(seq 1 90); do
  if curl -sS -o /dev/null "$KC/realms/master/.well-known/openid-configuration" 2>/dev/null; then
    echo "  up"; break
  fi
  sleep 2
done
TOKEN=$(admin_token)
echo "  admin token acquired"

# ---------------------------------------------------------------- realm setup
setup_realm() {
  local realm=$1
  kc_admin DELETE "/realms/$realm" >/dev/null 2>&1 || true
  kc_admin POST /realms "$(cat <<JSON
{"realm":"$realm","enabled":true,"resetPasswordAllowed":true,
 "smtpServer":{"host":"mailpit","port":"1025","from":"keycloak@example.org","auth":"","ssl":"","starttls":""}}
JSON
)" >/dev/null
}

say "Creating disposable realms (no user federation)"
setup_realm "$REALM"
setup_realm "$OTHER_REALM"
echo "  $REALM, $OTHER_REALM"

# role
kc_admin POST "/realms/$REALM/roles" \
  "{\"name\":\"$ROLE\",\"description\":\"Can trigger a password-reset email, nothing else\"}" >/dev/null

# clients: one with the role, one without
make_client() { # realm clientId
  kc_admin POST "/realms/$1/clients" "$(cat <<JSON
{"clientId":"$2","enabled":true,"publicClient":false,"serviceAccountsEnabled":true,
 "standardFlowEnabled":false,"directAccessGrantsEnabled":false,"implicitFlowEnabled":false,
 "fullScopeAllowed":false,"redirectUris":[],"webOrigins":[]}
JSON
)" >/dev/null
}
client_uuid() { kc_admin GET "/realms/$1/clients?clientId=$2" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])'; }
client_secret() { kc_admin GET "/realms/$1/clients/$2/client-secret" | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])'; }

make_client "$REALM" reset-caller
make_client "$REALM" norole-caller
make_client "$OTHER_REALM" reset-caller

CALLER_UUID=$(client_uuid "$REALM" reset-caller)
NOROLE_UUID=$(client_uuid "$REALM" norole-caller)
OTHER_UUID=$(client_uuid "$OTHER_REALM" reset-caller)

CALLER_SECRET=$(client_secret "$REALM" "$CALLER_UUID")
NOROLE_SECRET=$(client_secret "$REALM" "$NOROLE_UUID")
OTHER_SECRET=$(client_secret "$OTHER_REALM" "$OTHER_UUID")

# grant the role to reset-caller's service account only
SA_ID=$(kc_admin GET "/realms/$REALM/clients/$CALLER_UUID/service-account-user" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
ROLE_JSON=$(kc_admin GET "/realms/$REALM/roles/$ROLE" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(json.dumps([{"id":d["id"],"name":d["name"]}]))')
kc_admin POST "/realms/$REALM/users/$SA_ID/role-mappings/realm" "$ROLE_JSON" >/dev/null
echo "  clients created; role granted to reset-caller only"

# users
mkuser() { kc_admin POST "/realms/$1/users" "$2" >/dev/null; }
mkuser "$REALM" '{"username":"alice","enabled":true,"email":"alice@example.org","emailVerified":true}'
mkuser "$REALM" '{"username":"bob","enabled":false,"email":"bob@example.org"}'
mkuser "$REALM" '{"username":"carol","enabled":true}'
# An email-style username, to exercise '@' and '.'. Keycloak's user profile rejects characters
# like '&' outright (error-username-invalid-character), so there is no point testing those.
mkuser "$REALM" '{"username":"mario.rossi@example.org","enabled":true,"email":"mario@example.org"}'
echo "  users: alice (ok), bob (disabled), carol (no email), mario.rossi@example.org (ok)"

# a client with a registered redirect uri, to exercise redirect_uri relaying
kc_admin POST "/realms/$REALM/clients" \
  '{"clientId":"app","enabled":true,"publicClient":true,"standardFlowEnabled":true,
    "redirectUris":["https://app.example.org/*"]}' >/dev/null

# ---------------------------------------------------------------- helpers
svc_token() { # realm clientId secret
  curl -sS -X POST "$KC/realms/$1/protocol/openid-connect/token" \
    -d grant_type=client_credentials -d "client_id=$2" -d "client_secret=$3" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("access_token",""))'
}

reset_call() { # token realm query body -> status code
  curl -sS -o /tmp/prrp_body.$$ -w '%{http_code}' -X POST "$KC/realms/$2/password-reset$3" \
    -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -d "$4"
}

mail_clear() { curl -sS -X DELETE "$MAILPIT/api/v1/messages" >/dev/null; }
mail_count() { curl -sS "$MAILPIT/api/v1/messages" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("total",0))'; }

# Decodes the action token out of the newest email's link and prints one claim. This is how the
# security-critical assertions are made: the subject line is the generic "Update Your Account"
# executeActions template for every action, so it cannot distinguish them - the token can.
mail_token_claim() { # claim-name
  local id
  id=$(curl -sS "$MAILPIT/api/v1/messages" | python3 -c 'import sys,json;m=json.load(sys.stdin).get("messages") or [];print(m[0]["ID"] if m else "")')
  [ -n "$id" ] || { echo "<no-message>"; return; }
  curl -sS "$MAILPIT/api/v1/message/$id" | CLAIM="$1" python3 -c '
import sys, json, re, base64, os
d = json.load(sys.stdin)
text = (d.get("Text") or "") + (d.get("HTML") or "")
m = re.search(r"key=([A-Za-z0-9_\-\.]+)", text)
if not m:
    print("<no-token>"); raise SystemExit
p = m.group(1).split(".")[1]
p += "=" * (-len(p) % 4)
claims = json.loads(base64.urlsafe_b64decode(p))
want = os.environ["CLAIM"]
if want == "__validity__":
    print(int(claims["exp"]) - int(claims["iat"]))
else:
    print(json.dumps(claims.get(want)))'
}

expect() { # description expected actual
  if [ "$2" = "$3" ]; then ok "$1 ($3)"; else bad "$1 — expected $2, got $3 ; body: $(head -c 200 /tmp/prrp_body.$$ 2>/dev/null)"; fi
}

CALLER_TOKEN=$(svc_token "$REALM" reset-caller "$CALLER_SECRET")
NOROLE_TOKEN=$(svc_token "$REALM" norole-caller "$NOROLE_SECRET")
OTHER_TOKEN=$(svc_token "$OTHER_REALM" reset-caller "$OTHER_SECRET")
[ -n "$CALLER_TOKEN" ] && echo "  service-account tokens acquired" || { echo "could not get caller token"; exit 1; }

# ---------------------------------------------------------------- authorization
say "Authorization"
expect "no token -> 401" 401 "$(curl -sS -o /tmp/prrp_body.$$ -w '%{http_code}' -X POST \
  "$KC/realms/$REALM/password-reset" -H 'Content-Type: application/json' -d '{"username":"alice"}')"
expect "garbage token -> 401" 401 "$(reset_call "not.a.token" "$REALM" "" '{"username":"alice"}')"
expect "token from another realm -> 401" 401 "$(reset_call "$OTHER_TOKEN" "$REALM" "" '{"username":"alice"}')"
expect "client without the role -> 403" 403 "$(reset_call "$NOROLE_TOKEN" "$REALM" "" '{"username":"alice"}')"
expect "caller has no admin rights (GET /users) -> 403" 403 "$(curl -sS -o /dev/null -w '%{http_code}' \
  "$KC/admin/realms/$REALM/users" -H "Authorization: Bearer $CALLER_TOKEN")"

# ---------------------------------------------------------------- happy path
say "Happy path"
mail_clear
expect "existing enabled user with email -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"alice"}')"
sleep 2
if [ "$(mail_count)" = "1" ]; then ok "exactly one email captured in Mailpit"; else bad "expected 1 email, got $(mail_count)"; fi

say "Non-disclosure: unknown / disabled / email-less all look like success"
mail_clear
expect "unknown username -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"nosuchuser"}')"
expect "disabled user -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"bob"}')"
expect "user without email -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"carol"}')"
sleep 2
if [ "$(mail_count)" = "0" ]; then ok "no email sent for any of the three"; else bad "expected 0 emails, got $(mail_count)"; fi

say "Username handling"
mail_clear
expect "email-style username -> 204" 204 \
  "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"mario.rossi@example.org"}')"
sleep 2
if [ "$(mail_count)" = "1" ]; then ok "email sent for mario.rossi@example.org"; else bad "expected 1 email, got $(mail_count)"; fi
expect "missing username -> 400" 400 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{}')"
expect "blank username -> 400" 400 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"   "}')"
expect "malformed JSON -> 400" 400 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{not json')"

say "The hardcoded action is not caller-controlled (decoded from the action token)"
for attempt in '["UPDATE_EMAIL"]' '["delete_credential"]' '["CONFIGURE_TOTP"]' '[]'; do
  mail_clear
  code=$(reset_call "$CALLER_TOKEN" "$REALM" "" "{\"username\":\"alice\",\"actions\":$attempt}")
  sleep 2
  claim=$(mail_token_claim rqac)
  if [ "$code" = "204" ] && [ "$claim" = '["UPDATE_PASSWORD"]' ]; then
    ok "actions:$attempt ignored, token carries $claim"
  else
    bad "actions:$attempt -> status $code, token rqac=$claim (expected 204 / [\"UPDATE_PASSWORD\"])"
  fi
done

say "Relayed parameters"
mail_clear
expect "lifespan=60 -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "?lifespan=60" '{"username":"alice"}')"
sleep 2
V=$(mail_token_claim __validity__)
if [ "$V" = "60" ]; then ok "token validity honoured: ${V}s"; else bad "expected validity 60, got $V"; fi

mail_clear
expect "lifespan=999999 -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "?lifespan=999999" '{"username":"alice"}')"
sleep 2
V=$(mail_token_claim __validity__)
if [ "$V" = "3600" ]; then ok "token validity clamped to maxLifespanSeconds: ${V}s"; else bad "expected validity clamped to 3600, got $V"; fi

mail_clear
expect "no lifespan -> 204" 204 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"alice"}')"
sleep 2
V=$(mail_token_claim __validity__)
if [ "$V" = "3600" ]; then ok "default validity is the cap, not the realm's 43200: ${V}s"; else bad "expected default validity 3600, got $V"; fi

expect "lifespan=abc -> 400" 400 "$(reset_call "$CALLER_TOKEN" "$REALM" "?lifespan=abc" '{"username":"alice"}')"
expect "lifespan=0 -> 400" 400 "$(reset_call "$CALLER_TOKEN" "$REALM" "?lifespan=0" '{"username":"alice"}')"
expect "redirect_uri without client_id -> 400" 400 \
  "$(reset_call "$CALLER_TOKEN" "$REALM" "?redirect_uri=https%3A%2F%2Fapp.example.org%2Fdone" '{"username":"alice"}')"
expect "unknown client_id -> 400" 400 \
  "$(reset_call "$CALLER_TOKEN" "$REALM" "?client_id=nosuchclient" '{"username":"alice"}')"
expect "redirect_uri not allowed for client -> 400" 400 \
  "$(reset_call "$CALLER_TOKEN" "$REALM" "?client_id=app&redirect_uri=https%3A%2F%2Fevil.example.org%2F" '{"username":"alice"}')"
expect "valid client_id + redirect_uri -> 204" 204 \
  "$(reset_call "$CALLER_TOKEN" "$REALM" "?client_id=app&redirect_uri=https%3A%2F%2Fapp.example.org%2Fdone" '{"username":"alice"}')"

say "Fail closed when the role does not exist"
kc_admin DELETE "/realms/$REALM/roles/$ROLE" >/dev/null
TOKEN=$(admin_token)
expect "role deleted -> 403" 403 "$(reset_call "$CALLER_TOKEN" "$REALM" "" '{"username":"alice"}')"

rm -f /tmp/prrp_body.$$
say "Result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
