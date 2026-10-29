# real-vm/ — offsets & taking the PoC to a real target

The lab targets are self-contained, but a real engagement needs the target build's
own offsets. Everything here is about getting them and driving the PoC with them.

## Files

| File | What it does |
|---|---|
| `offsets_db.json` | Per-build offset database, keyed by GNU build-id (exact) and PHP version (fuzzy). Seeded from the four official `php:8.x-apache` builds. |
| `p2s_target_vars.sh` | **Self-contained** (python3 only). Reads `zif`/`dtor` offsets out of a `libphp.so` (symbols, or a dbgsym debug object if stripped), its build-id, and the PHP minor (→ `htdata`). Run it on a target, or point it at a copy of the target's module. |
| `p2s_offtest.sh` | Drive the PoC with offsets from a file (`--libphp`), an env file (`--env`), or flags (`--zif/--dtor/--htdata`). Blind by default; `--proof` for the HTTP-readback proof. |
| `p2s_offsets.py` | Offset-DB resolve / extract helpers (list, resolve by build-id or version, extract from a `libphp.so`). |
| `p2s_matrix.py` | Fingerprint → resolve → blind-probe a list of targets and render a results table (`../POC_MATRIX.md`). |
| `OFFSETS_FROM_TARGET.md` | The two real-target workflows, documented end to end. |

## The short version

```bash
# you have a copy of the target's libphp.so:
./p2s_offtest.sh -u http://target/ --libphp /path/to/libphp.so

# you only have a shell on the target:
./p2s_target_vars.sh --env > vars.env        # run ON the target
./p2s_offtest.sh -u http://target/ --env vars.env
```

See `OFFSETS_FROM_TARGET.md` for the details (dbgsym for stripped builds, what the
exploit must still leak live, etc.).
