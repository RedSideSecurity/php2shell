# p2s_scan.py — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) scanner

Single file, Python 3 standard library only (no pip install).

    python3 p2s_scan.py -u http://127.0.0.1:8082              # one URL
    python3 p2s_scan.py -u URL1 -u URL2                       # several
    python3 p2s_scan.py -l urls.txt -t 5 -o results.csv       # list file (or .json)

Options: `-t` parallel targets (5) · `--timeout` secs (30) · `-k` ignore TLS cert errors (+ allow old TLS/ciphers) ·
`--quick` only the 1 MiB probe · `--no-color`. Exit code 1 if anything is VULNERABLE, 2 if only POTENTIAL, else 0.
No path in the URL → `/index.php`. `urls.txt`: one URL per line, `#` = comment.

| Verdict | Meaning |
|---|---|
| VULNERABLE | confirmed: the page shows PHP's out-of-memory fatal error "in Unknown" raised while parsing the probe |
| POTENTIAL | indirect sign only: empty 500/200 vs normal page, 502/503/504 (FPM worker died), dropped connection, or banner = unpatched release — verify manually |
| SAFE | PHP stopped at "Multipart body parts limit exceeded" (patched behaviour), or banner = fixed release (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12+) |
| UNKNOWN | no signal: errors hidden + no banner, WAF/proxy rejected (4xx), control already 5xx, timeout, not PHP |
| ERROR | connection failed |

Probes are byte-identical to assetnote/php2shell-scanner (1/8/20 MiB, 62-deep keys, empty boundary).
Caveats: patched PHP with very low memory_limit (2M–32M) or max_multipart_body_parts ≥ 2785 can
also OOM → false VULNERABLE; distro backports keep old version numbers → banner verdicts are leads.
Each probe kills the PHP request — scan only systems you are authorised to test.
