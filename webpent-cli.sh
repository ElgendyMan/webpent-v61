#!/usr/bin/env bash
set -euo pipefail
API_URL="${WEBPENT_API_URL:-http://localhost:8000}"
DB_PATH="${WEBPENT_DB_PATH:-./webpent.db}"
if [ $# -lt 1 ]; then
    echo "Usage: $0 <target_url> [--auto-approve] [--stealth]"; exit 1
fi
TARGET_URL="$1"; shift; EXTRA=""; AUTO=false
while [ $# -gt 0 ]; do
    case "$1" in
        --auto-approve) AUTO=true; shift ;;
        --stealth) EXTRA="$EXTRA --stealth"; shift ;;
        *) shift ;;
    esac
done
THREAD_ID=""
mkdir -p logs
echo "=== WebPent V7 CLI ==="
echo "Target: $TARGET_URL"
RESPONSE=$(curl -sf -X POST "$API_URL/api/v1/scans" -H "Content-Type: application/json" -d "{\"url\": \"$TARGET_URL\", \"auto_approve\": $AUTO}" 2>&1) || { echo "FAIL: API unreachable"; exit 1; }
THREAD_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('thread_id',''))" 2>/dev/null || echo "")
[ -z "$THREAD_ID" ] && { echo "FAIL: no thread_id"; exit 1; }
echo "Thread: $THREAD_ID"
if [ "$AUTO" = "false" ]; then
    while true; do
        STATUS=$(curl -sf "$API_URL/api/v1/scans/$THREAD_ID/status" 2>/dev/null || echo "{}")
        PAUSED=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('is_paused_at_sandbox',False))" 2>/dev/null || echo "False")
        [ "$PAUSED" = "True" ] && break
        SSTAT=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
        [ "$SSTAT" = "completed" ] || [ "$SSTAT" = "error" ] && { THREAD_ID=""; break; }
        sleep 3
    done
    [ -n "$THREAD_ID" ] && curl -sf -X POST "$API_URL/api/v1/scans/$THREAD_ID/approve" >/dev/null 2>&1
fi
[ -n "$THREAD_ID" ] && while true; do
    STATUS=$(curl -sf "$API_URL/api/v1/scans/$THREAD_ID/status" 2>/dev/null || echo "{}")
    SSTAT=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")
    [ "$SSTAT" = "completed" ] || [ "$SSTAT" = "error" ] || [ "$SSTAT" = "terminated_recursion_limit" ] && break
    sleep 5
done
echo "=== Findings ==="
python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$DB_PATH')
    conn.row_factory = sqlite3.Row
    for r in conn.execute('SELECT title,severity,vuln_class,confidence_level FROM findings ORDER BY created_at DESC'):
        print(f'  [{r[\"severity\"]:>8}] [{r[\"vuln_class\"]:>15}] {r[\"title\"][:60]}')
    conn.close()
except Exception as e:
    print(f'Error: {e}')
"
