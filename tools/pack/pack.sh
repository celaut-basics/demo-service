#!/bin/bash
# Pack the verifier for one architecture, children first, on a node with nodo #538.
#
#   tools/pack/pack.sh <arch> [stage dir]      (amd64 or arm64; run from the repository root)
#
# Each child is packed on its own, then family is packed with tiny's id, then the
# verifier with every id, from copies that stamp.py names by hash (see stamp.py: the
# children's ids are not reproducible, so the repository's service.json files carry
# none). The ids go to <stage dir>/ids.env, one NAME=<id> per line.
set -euo pipefail
ARCH=${1:?amd64 or arm64}
STAGE=${2:-/tmp/demo-pack-$ARCH}
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$STAGE"
IDS="$STAGE/ids.env"
: > "$IDS"

pack() {  # pack <dir> -> service id on stdout; the log in $STAGE
    local dir=$1
    local log="$STAGE/pack-$(basename "$(dirname "$dir")")-$(basename "$dir").log"
    nodo pack "$dir" --local --json > "$log" 2>&1 || { echo "pack of $dir failed, see $log" >&2; exit 1; }
    grep -o '"service_id": *"[0-9a-f]\{64\}"' "$log" | tail -1 | grep -o '[0-9a-f]\{64\}'
}

declare -A ID
for pair in TINY:tiny HEAVY:heavy PING:ping BENCHMARK:benchmark SHAREFS:sharefs \
            SHAREFS_DENIED:sharefs-denied NETSHARE:netshare; do
    name=${pair%%:*} dir=${pair#*:}
    ID[$name]=$(pack "$dir/$ARCH")
    echo "$name=${ID[$name]}" | tee -a "$IDS"
done
python3 "$HERE/stamp.py" "family/$ARCH" family "$STAGE/family" "TINY=${ID[TINY]}" > /dev/null
ID[FAMILY]=$(pack "$STAGE/family")
echo "FAMILY=${ID[FAMILY]}" | tee -a "$IDS"
args=()
for name in "${!ID[@]}"; do args+=("$name=${ID[$name]}"); done
python3 "$HERE/stamp.py" "$ARCH" verifier "$STAGE/verifier" "${args[@]}" > /dev/null
VERIFIER=$(pack "$STAGE/verifier")
echo "VERIFIER=$VERIFIER" | tee -a "$IDS"
