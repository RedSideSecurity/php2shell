#!/bin/sh
# Build and start all four labs, bound to localhost only.
# 8.2 -> :8082, 8.3 -> :8083, 8.4 -> :8084, 8.5 -> :8085
#
# Realistic target: NO host-mounted proof dir, NO pre-staged payload, nothing a
# real server wouldn't have. Proof comes from the exploit itself --
#   - blind sleep-timing (writes nothing), or
#   - a `poc` file dropped in the server cwd (webroot, owned by www-data as on a
#     normal self-updating PHP app) and read back over HTTP.
# Drive it with:  python3 p2s.py -u http://127.0.0.1:8084/
cd "$(dirname "$0")"
for b in 8.2 8.3 8.4 8.5; do
  p=808${b#8.}
  docker build -q -t php2shell-lab:$b php-$b >/dev/null || exit 1
  docker rm -f php2shell-$b >/dev/null 2>&1
  docker run -d --name php2shell-$b -p 127.0.0.1:$p:80 \
    php2shell-lab:$b >/dev/null \
    && echo "php2shell-$b -> http://127.0.0.1:$p/"
done
