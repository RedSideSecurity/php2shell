# Getting the per-build variables for a real target

The php2shell PoC needs three per-build constants it can't know in advance:

| Variable | What it is | Source |
|---|---|---|
| `zif_offset`   | offset of `zif_system` inside `libphp.so`    | **symbol in the binary** |
| `dtor_offset`  | offset of `zval_ptr_dtor` inside `libphp.so`  | **symbol in the binary** |
| `htdata_offset`| heap-layout constant, keyed to the PHP **minor** | version → table (sweepable) |

All three come out of the target's **`libphp.so`** — `zif`/`dtor` are symbols in
it, and the PHP minor (which fixes `htdata`) is embedded in it too.

What you still **cannot** get ahead of time: the two **ASLR bases** (the live
address of the heap, and of `libphp.so`). Those are randomised every request and
the exploit **leaks them itself** at run time. The tools below only close the
"exact-build" gap.

---

## Easiest path — you have a copy of the target's `libphp.so`

You usually do: copy it off the box, or `apt-get download` the matching distro
package (same package version = same build-id = same offsets). Hand the file to
the tester and it does everything:

```bash
./real-vm/p2s_offtest.sh -u http://TARGET/ --libphp /path/to/libphp.so
```

It parses the file → derives `zif`/`dtor`/`htdata` → runs the **blind** verifier
(`sleep 8`, writes nothing). Add `--proof` to drop+read a `poc` file instead.

Where is `libphp.so` on a typical box? `/usr/lib/apache2/modules/libphp.so`
(Debian/Ubuntu mod_php), `/usr/lib64/httpd/modules/libphp.so` (RHEL). For
php-fpm the symbols are in the `php-fpm` binary itself — pass that.

## Only have a shell on the target

Run the self-contained extractor **on the target** (needs only `python3`):

```bash
./p2s_target_vars.sh                 # auto-finds libphp.so, prints the 3 vars
./p2s_target_vars.sh --env > vars.env
```

It prints a ready-to-paste tester command. Copy the values to your attacker box:

```bash
./real-vm/p2s_offtest.sh -u http://TARGET/ --env vars.env
# or spell them out:
./real-vm/p2s_offtest.sh -u http://TARGET/ --zif 0x.. --dtor 0x.. --htdata 0x..
```

## Stripped binary?

If `libphp.so` is fully stripped, `zif_system`/`zval_ptr_dtor` aren't in it.
Install the matching debug package and the extractor follows it automatically:

```bash
sudo apt-get install libapache2-mod-php8.4-dbgsym   # Debian/Ubuntu ddebs
```

(The official `php:8.x-apache` Docker images are **not** stripped — the symbols
are present, so no dbgsym is needed there.)

---

## Notes

- `htdata_offset` is **not** a symbol; it's keyed to the PHP minor
  (8.3 → `0x6A0D8`, 8.4/8.5 → `0x690D8`). For a build the table doesn't cover,
  the tester sweeps `±K` pages (`--sweep`, default 2) around the guess.
- `zif`/`dtor` are exact and build-specific — a different patch level, distro or
  compiler gives different numbers. Always derive them from **that** target's
  binary, never reuse another box's.
- The blind verifier is the safe default: it proves yes/no with a timed
  `sleep` and leaves no artifact. Use `--proof` only for an authorized demo.
