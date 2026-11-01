#!/bin/sh
# Compile the actual pinned header with both include orders used by upstream.
# No replacement obfs_t declaration or disabled validation is accepted.
set -eu
src=${1:?SSR source checkout is required}
build=${2:?SSR configured build directory is required}
test "$(git -C "$src" rev-parse HEAD)" = 227127c4bc5a6555e0556693d084c96860e75b5e
test -f "$build/config.h"
owned=$(mktemp -d)
trap 'rm -rf "$owned"' EXIT HUP INT TERM
mkdir "$owned/upstream"
git -C "$src" show HEAD:src/obfs/obfs.h >"$owned/upstream/obfs.h"

cat >"$owned/early.c" <<'C'
#include <stddef.h>
#include "obfs.h"
#include "config.h"
const size_t early_layout[] = {
    sizeof(struct obfs_t),
    offsetof(struct obfs_t, generate_global_init_data),
    offsetof(struct obfs_t, get_overhead),
    offsetof(struct obfs_t, dispose),
    offsetof(struct obfs_t, server_udp_post_decrypt)
};
C
cat >"$owned/late.c" <<'C'
#include <stddef.h>
#include "config.h"
#include "obfs.h"
extern const size_t early_layout[];
int main(void) {
    const size_t late_layout[] = {
        sizeof(struct obfs_t),
        offsetof(struct obfs_t, generate_global_init_data),
        offsetof(struct obfs_t, get_overhead),
        offsetof(struct obfs_t, dispose),
        offsetof(struct obfs_t, server_udp_post_decrypt)
    };
    size_t i;
    for (i = 0; i < sizeof(late_layout) / sizeof(late_layout[0]); ++i) {
        if (early_layout[i] != late_layout[i]) { return 17; }
    }
    return 0;
}
C

${CC:-cc} -O3 -DNDEBUG -std=c99 -Wall -Wextra -Werror \
    -I"$src/src/obfs" -I"$build" "$owned/early.c" "$owned/late.c" -o "$owned/patched"
"$owned/patched"
${CC:-cc} -O3 -DNDEBUG -std=c99 -Wall -Wextra -Werror \
    -I"$owned/upstream" -I"$build" "$owned/early.c" "$owned/late.c" -o "$owned/upstream-control"
status=0
"$owned/upstream-control" || status=$?
if [ "$status" -ne 17 ]; then
    echo "Pinned unpatched SSR include-order control did not expose its ABI mismatch: $status" >&2
    exit 1
fi
echo 'PASS pinned SSR optimized mixed-include ABI; unpatched control rejected'
