#!/bin/bash
# login-helper — Juice Shop two-user token fetcher
#
# Purpose: provide the LLM agent with authenticated sessions for two
# different privilege levels (user + admin) so it can perform
# differential IDOR / access-control probes.
#
# This script is INTENTIONALLY DUMB. It does NOT interpret responses,
# it does NOT flag IDOR, it does NOT make any security judgement.
# It just logs in twice and prints the credentials as JSON.
#
# Usage:
#   login-helper                  # default target http://juice-shop:3000
#   login-helper <target_url>     # override target
#
# Output: JSON with two {email, token, cookie_file} blocks.
# Cookie jars are written to /tmp/{user,admin}.jar for reuse with curl --cookie.

set -e

TARGET="${1:-http://juice-shop:3000}"
# Juice Shop well-known demo credentials (seeded by the app on first run)
USER_EMAIL="jim@juice-sh.op"
USER_PASS="ncc-1701"
ADMIN_EMAIL="admin@juice-sh.op"
ADMIN_PASS="admin123"
USER_JAR="/tmp/user.jar"
ADMIN_JAR="/tmp/admin.jar"

login() {
    local email="$1"
    local password="$2"
    local jar="$3"
    curl -s -c "$jar" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${email}\",\"password\":\"${password}\"}" \
        "${TARGET}/rest/user/login" 2>/dev/null || echo '{}'
}

extract_token() {
    # Extract "token":"..." from the login response JSON.
    # Fallback: empty string if login failed.
    echo "$1" | grep -o '"token":"[^"]*"' | head -1 | sed 's/"token":"//;s/"$//'
}

USER_RESP=$(login "$USER_EMAIL" "$USER_PASS" "$USER_JAR")
USER_TOKEN=$(extract_token "$USER_RESP")

ADMIN_RESP=$(login "$ADMIN_EMAIL" "$ADMIN_PASS" "$ADMIN_JAR")
ADMIN_TOKEN=$(extract_token "$ADMIN_RESP")

cat <<EOF
{
  "target": "${TARGET}",
  "user":  { "email": "${USER_EMAIL}",  "token": "${USER_TOKEN}",  "cookie_file": "${USER_JAR}" },
  "admin": { "email": "${ADMIN_EMAIL}", "token": "${ADMIN_TOKEN}", "cookie_file": "${ADMIN_JAR}" },
  "hint": "Use --cookie ${USER_JAR} or --cookie ${ADMIN_JAR} with curl, or add 'Authorization: Bearer <token>' header. Then pass both responses to diff-view to compare."
}
EOF
