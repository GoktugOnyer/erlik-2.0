#!/bin/bash
# diff-view — HTTP response diff viewer
#
# Purpose: let the LLM agent compare two HTTP responses side-by-side
# (typically the SAME URL requested with two different credentials)
# to enable differential IDOR / access-control analysis.
#
# This script is INTENTIONALLY DUMB. It does NOT emit "IDOR detected".
# It does NOT classify the result. It just fetches, hashes, and diffs.
# The LLM reads the output and decides if it's a finding.
#
# Usage:
#   diff-view <url_a> <url_b>
#   diff-view <url_a> <url_b> --cookie-a /tmp/user.jar --cookie-b /tmp/admin.jar
#   diff-view <url_a> <url_b> --header-a "Authorization: Bearer $TOK1" \
#                             --header-b "Authorization: Bearer $TOK2"
#
# Output: unified diff of the two responses with status, length,
# SHA-256, and the first 2000 lines of body diff.

set -e

if [ $# -lt 2 ]; then
    echo "Usage: diff-view <url_a> <url_b> [--cookie-a FILE] [--cookie-b FILE] [--header-a STR] [--header-b STR]"
    exit 1
fi

URL_A="$1"
URL_B="$2"
shift 2

# Use bash arrays so values with spaces (e.g. 'Authorization: Bearer xxx') survive.
CURL_A=()
CURL_B=()

while [ $# -gt 0 ]; do
    case "$1" in
        --cookie-a) CURL_A+=(--cookie "$2"); shift 2 ;;
        --cookie-b) CURL_B+=(--cookie "$2"); shift 2 ;;
        --header-a) CURL_A+=(-H "$2"); shift 2 ;;
        --header-b) CURL_B+=(-H "$2"); shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

TMP_A="$(mktemp)"
TMP_B="$(mktemp)"
HEAD_A="$(mktemp)"
HEAD_B="$(mktemp)"

curl -s -D "$HEAD_A" -o "$TMP_A" "${CURL_A[@]}" "$URL_A" || true
curl -s -D "$HEAD_B" -o "$TMP_B" "${CURL_B[@]}" "$URL_B" || true

STATUS_A=$(head -1 "$HEAD_A" | awk '{print $2}')
STATUS_B=$(head -1 "$HEAD_B" | awk '{print $2}')
LEN_A=$(wc -c < "$TMP_A")
LEN_B=$(wc -c < "$TMP_B")
SHA_A=$(sha256sum "$TMP_A" | awk '{print $1}')
SHA_B=$(sha256sum "$TMP_B" | awk '{print $1}')

echo "=== diff-view ==="
echo "URL A: $URL_A"
echo "URL B: $URL_B"
echo ""
echo "| Metric        | A                                  | B                                  |"
echo "|---------------|------------------------------------|------------------------------------|"
printf "| HTTP Status   | %-34s | %-34s |\n" "$STATUS_A" "$STATUS_B"
printf "| Content-Length| %-34s | %-34s |\n" "$LEN_A" "$LEN_B"
printf "| SHA-256       | %s | %s |\n" "${SHA_A:0:34}" "${SHA_B:0:34}"
echo ""

if [ "$SHA_A" = "$SHA_B" ]; then
    echo "BODIES IDENTICAL (SHA-256 match). No access-control difference visible at this URL."
else
    echo "BODIES DIFFER. Unified diff (first 2000 lines):"
    echo ""
    diff -u "$TMP_A" "$TMP_B" | head -2000 || true
fi

rm -f "$TMP_A" "$TMP_B" "$HEAD_A" "$HEAD_B"
