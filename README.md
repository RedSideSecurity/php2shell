<div align="center">

# php2shell

**A realistic, self-contained lab + toolkit for CVE-2026-109618 / CVE-2026-109619 — the PHP "php2shell" pre-auth RCE.**

Detect it. Prove it. Understand it. On a lab that behaves like a real server, not a rigged demo.

_by [RedSide Security](https://github.com/RedSideSecurity)_

</div>

---

## TL;DR

```bash
git clone https://github.com/RedSideSecurity/php2shell
cd php2shell
./run.sh                                   # builds + starts 4 labs on 127.0.0.1:8082-8085

python3 scanner/p2s_scan.py -u http://127.0.0.1:8084/     # detect   -> VULNERABLE
python3 p2s.py -u http://127.0.0.1:8084/ --no-poc         # prove    -> RCE CONFIRMED (blind)
```

Four official PHP versions (8.2 / 8.3 / 8.4 / 8.5), a detection scanner, a **blind**
exploitability verifier that writes nothing, and the per-build offset tooling you
need to carry a test to a real target. No shared folders. No planted files. No LFI.

---

## What is php2shell?

`php2shell` is the nickname for two PHP-core memory-safety flaws disclosed and patched
in October 2026:

- **CVE-2026-109618** — a use-after-free in `zend_hash` array cleanup. During array
  destruction, a destructor can resize the same array, freeing its backing buffer
  while the cleanup loop still walks it. An attacker who reoccupies that freed buffer
  controls a fake `HashTable` whose `pDestructor` is called — turning the bug into
  `system()`. This is the path to **pre-authentication remote code execution**.
- **CVE-2026-109619** — a related instability in the multipart / `session.upload_progress`
  request path, reachable with no application cooperation (no `session_start()` needed).

The bug lives in PHP's request parsing and cleanup — **not** in your application code.
Any mod_php / Apache deployment on an unpatched 8.3 / 8.4 / 8.5 is a candidate.

> **Fixed in** 8.2.35 · 8.3.36 · 8.4.27 · 8.5.12. If you run PHP, patch.

---

## Why this lab is different

Most public "php2shell PoCs" quietly make the target easy so the demo always lands.
They tend to do one or more of these:

| The shortcut others take | Why it's not a real proof |
|---|---|
| **Bind-mount a shared folder** (`-v ./out:/out`) and have the exploit write its proof there | You're reading a file over a Docker volume you control — not over the network from a server you don't. It hides whether the exploit could ever exfiltrate on a real box. |
| **`chmod 777` a world-writable drop dir** baked into the image | Real servers don't ship a world-writable, web-served scratch dir. The "write + read back" only works because the lab pre-arranged it. |
| **Combine the bug with a separate LFI / file-read** to fetch a planted payload | That proves *two* bugs chained in a lab, not that php2shell alone gives you execution. It launders a weak result into a shiny one. |
| **Pre-stage the payload** inside the image, then "trigger" it | The hard part (getting controlled bytes to execute) is skipped; you're firing a starter pistol next to a pre-loaded gun. |

**This lab removes every one of those crutches.** The containers are stock
`php:8.x-apache` images with a realistic config, and the proof comes out of the
**exploit itself**:

- ✅ **No `-v` volume mounts.** Nothing is shared between host and container.
- ✅ **No world-writable dirs.** The webroot is owned by `www-data` with normal
  permissions — exactly like a self-updating CMS — so the one place the exploit can
  write is the same place a real compromised app could.
- ✅ **No LFI, no second bug.** php2shell is the *only* vulnerability in the chain.
- ✅ **No pre-staged payload.** The command is carried by the exploit, live.
- ✅ **Proof travels the way a real one would:** either a **blind sleep-timing**
  signal (the request hangs for `N` seconds — nothing is written at all), or a file
  the exploit drops into the normal webroot and then **reads back over HTTP**.

If it lands here, it lands because the vulnerability actually gives you execution —
not because the lab handed it to you.

---

## Repository layout

```
php2shell/
├── run.sh / stop.sh            build + start / stop the four labs (127.0.0.1 only)
├── php-8.2 .. php-8.5/         one realistic Docker target per PHP minor
│     Dockerfile                stock php:8.x-apache + www-data-owned webroot (no 777, no mount)
│     apache.conf               single-worker prefork (deterministic heap grooming)
│     php2shell.ini             8M memory_limit, upload_progress on — a normal small host
│     index.php / info.php      a plain landing page (+ a diagnostics page)
│
├── scanner/                    DETECT
│     p2s_scan.py               stdlib-only, safe OOM-differential detector (-u / -l / -o)
│
├── p2s.py                      PROVE (one command): fingerprint -> offsets -> blind check -> optional HTTP-readback proof
├── exploit/
│     p2s_verify.py             blind, no-artifact verifier (sleep-timing only)
│     php2shell-dynamic-aslr.patch   host-agnostic ASLR calibration
│     engine/                   low-level UAF chain primitive (third party, MIT — see NOTICE)
│
├── real-vm/                    TAKE IT TO A REAL TARGET
│     offsets_db.json           per-build offset database (keyed by GNU build-id)
│     p2s_target_vars.sh        run on a target: read its offsets out of libphp.so
│     p2s_offtest.sh            run the PoC with offsets from a file / flags / env
│     p2s_offsets.py            offset DB resolve / extract helpers
│     OFFSETS_FROM_TARGET.md    the two real-target workflows, documented
│
└── probe/                      optional 109619 reachability validators
```

---

## The three things you can do

### 1 · Detect — `scanner/p2s_scan.py`

A dependency-free, **non-destructive** detector. It sends a small multipart probe and
reads the in-band out-of-memory differential that the unpatched parser produces; a
patched build answers with a "multipart body parts limit exceeded" message instead.

```bash
python3 scanner/p2s_scan.py -u http://target/                 # one host
python3 scanner/p2s_scan.py -l hosts.txt -o csv > out.csv     # a list
```

Verdicts: `VULNERABLE` (in-band OOM), `POTENTIAL` (ambiguous 500 / banner only),
`SAFE`, `UNKNOWN`, `ERROR`. No exploitation, nothing written.

### 2 · Prove — `p2s.py` / `exploit/p2s_verify.py`

`p2s.py` is the one-command driver: it fingerprints the PHP version, pulls the matching
offsets from the database (sweeping the heap-layout constant), runs a **blind** check,
and only then (optionally) drops a readable proof file and fetches it back over HTTP.

```bash
python3 p2s.py -u http://target/ --no-poc        # blind only — writes NOTHING
python3 p2s.py -u http://target/                 # + HTTP-readback proof (overt)
```

The blind verifier on its own, for engagements where you want a pure yes/no and zero
footprint:

```bash
python3 exploit/p2s_verify.py -u http://target/ --sleep 8
# -> "RCE CONFIRMED: command executed (request delayed ~8s)"
```

It runs `sleep N` (7 bytes — see the 14-byte note below) through the chain and times
the response. A normal request returns in well under a second; if the destructor ran,
the response is delayed ~N seconds. **That delay is the proof. Nothing is written,
nothing is exfiltrated.**

### 3 · Take it to a real target — `real-vm/`

The exploit needs three per-build constants. Two (`zif`, `dtor`) are symbol offsets
inside the target's `libphp.so`; the third (`htdata`) is keyed to the PHP minor. All
three can be read straight out of a copy of the target's own module:

```bash
# easiest: you have the target's libphp.so on your box
./real-vm/p2s_offtest.sh -u http://target/ --libphp /path/to/libphp.so

# or only a shell on the target: extract there, carry the numbers over
./real-vm/p2s_target_vars.sh --env > vars.env
./real-vm/p2s_offtest.sh -u http://target/ --env vars.env
```

What you **cannot** pre-compute — and what the exploit leaks live each run — are the two
ASLR bases (where the heap and `libphp.so` are mapped this request). See
[`real-vm/OFFSETS_FROM_TARGET.md`](real-vm/OFFSETS_FROM_TARGET.md).

---

## Why it's hard to exploit (and why that matters)

php2shell is a real pre-auth RCE, but it is **not** a push-button worm. To fire it you
must line up, at the same instant:

- **Exact per-build offsets** — tied to one `libphp.so`; a different patch level, distro
  or compiler changes the numbers, and a wrong guess crashes the worker.
- **Two live info-leaks** — ASLR randomizes the heap and code bases every request; you
  have to steal both before you can aim anything.
- **A groomed heap** — the free-and-refill race only wins when memory is in the expected
  shape (ideally a single worker); real traffic perturbs it.

Miss any one and you get a segfault, not a shell. The bug is universal; the parameters
are bespoke — which is exactly why realistic labs matter, and why a lab that mounts a
shared folder tells you nothing about a real target.

### The 14-byte command

The command rides inside a fixed **167-byte** heap object alongside a forged `HashTable`,
`execute_data`, and string header. The command field is just the tail: `167 − 152 − 1`
(NUL) = **14 bytes**. That's enough to prove RCE (`sleep 8`) or to load more
(`sh</tmp/c`, an 8-byte loader for an arbitrarily long staged script). It is a structural
limit, not a configurable one.

---

## Verified results

Tested against this lab (localhost, official images):

| PHP build | Scanner | Offsets from `libphp.so` | Blind RCE |
|---|---|---|---|
| 8.2.34 | VULNERABLE | zif `0x39b8a0` · dtor `0x487650` | not exploitable by this chain |
| 8.3.35 | VULNERABLE | zif `0x3ac080` · dtor `0x49ec50` · htd `0x6A0D8` | ✅ confirmed |
| 8.4.26 | VULNERABLE | zif `0x465370` · dtor `0x65eb60` · htd `0x690D8` | ✅ confirmed |
| 8.5.11 | VULNERABLE | zif `0x5996e0` · dtor `0x7b47a0` · htd `0x690D8` | ✅ confirmed |

8.2 is flagged by the scanner (the parser OOMs) but is not exploitable by this specific
destructor chain.

---

## Requirements

- Docker (first `run.sh` pulls the official `php:8.x-apache` images — needs internet once)
- Python 3 (standard library only; no pip packages)

The labs bind to `127.0.0.1` only. Stop them with `./stop.sh`.

---

## Responsible use

This toolkit is for **authorized** work only: your own lab, a system you own, or an
engagement with written permission. php2shell is a patched CVE — the single most
effective control is to **update PHP**. The default proof methods here are deliberately
restrained (non-destructive scan, blind timing, overt webroot read-back) precisely so
they can be used in a real assessment without covert staging or data exfiltration.

Don't point any of this at systems you don't have permission to test.

---

## License

MIT — see [LICENSE](LICENSE). Third-party components and their licenses are listed in
[NOTICE](NOTICE).
