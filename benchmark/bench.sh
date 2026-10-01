#!/bin/sh
# bench.sh -- per-core micro-benchmarks of the machine this service runs on.
#
# A nodo node runs this service as its optional `benchmark` core service and
# writes what it returns into its own config.yaml, per architecture
# (celaut-project/nodo#459). Those numbers are what a service's
# `resources.at_init.benchmark` requirement is held against at admission, so
# every one of them is per core and per second, and every node measures them
# with the same code: this file, inside an image pinned by content hash.
#
# Prints one `key=value` line per measured primitive, integers only:
#
#   int_ops_per_sec                  ash integer LCG steps per second
#   flt_ops_per_sec                  awk floating-point multiply-adds per second
#   mem_bandwidth_bytes_per_sec      bytes written per second through a buffer
#   mem_bandwidth_working_set_bytes    of this size (see below)
#   sha256_hashes_per_sec            SHA-256 digests of 64-byte inputs per second
#
# A primitive that cannot be measured prints `skipped <key>: <reason>` instead
# and its line is simply absent: a missing score is unmeasured, never 0.
#
# Usage: bench.sh [working_set_bytes]
#
# Design (ported from celaut-project/nodo#457, which ran the same loops inside
# the guest initramfs):
#
# * Time comes from /proc/uptime only, read with the `read` builtin so taking a
#   reading costs no fork. It has centisecond resolution, so each primitive runs
#   for BENCH_CS centiseconds (2 s by default) to keep the error near 0.5%.
#   `date` is not used: busybox's has no portable sub-second format.
# * Every loop is single-process, so a score is what ONE core does.
# * Memory bandwidth uses `dd bs=<working set>`: the buffer is the working set,
#   and only a working set larger than the last-level cache measures memory
#   rather than cache. The fault-in of the buffer and the cost of starting dd
#   are cancelled by timing count=c and count=2c and dividing the extra c
#   blocks by the extra time.
# * SHA-256 hashes 256 files per `sha256sum` process, so what is measured is
#   hashing and not fork+exec.

# The pinned default working set: 1 GiB. Larger than any last-level cache a
# single core can use today (the largest unified LLCs ship at ~0.5 GiB, e.g.
# Xeon 6980P's 504 MB; AMD's 3D V-Cache parts reach 1 GiB+ in total but only
# ~96 MiB per CCD is visible to one core), and well below the 2 GiB this
# service declares as its memory (service.json), leaving ~1 GiB for the kernel,
# busybox and the page cache. nodo pins the same number
# (src/utils/benchmark.py::DEFAULT_MEM_BANDWIDTH_WORKING_SET_BYTES): a
# requirement that names no working set is read against it.
DEFAULT_WORKING_SET_BYTES=1073741824

BENCH_CS=${BENCH_CS:-200}
BENCH_TMP=${BENCH_TMP:-${TMPDIR:-/tmp}}
# Overridable only so the tests can feed now_cs a fixed reading.
BENCH_UPTIME=${BENCH_UPTIME:-/proc/uptime}

# NOW <- centiseconds since boot. "1${_f}" - 100 rather than $_f: a fraction
# like ".08" is an octal literal to the shell's arithmetic, and "8" and "9"
# digits make it an error rather than merely a wrong number.
now_cs() {
    read -r _up _idle < "$BENCH_UPTIME"
    _s=${_up%.*}
    _f=${_up#*.}
    NOW=$(( _s * 100 + 1${_f} - 100 ))
}

bench_int() {
    _x=1
    _n=0
    now_cs
    _start=$NOW
    _end=$(( _start + BENCH_CS ))
    while :; do
        _i=0
        while [ $_i -lt 1000 ]; do
            _x=$(( (_x * 1103515245 + 12345) & 2147483647 ))
            _i=$(( _i + 1 ))
        done
        _n=$(( _n + 1000 ))
        now_cs
        [ "$NOW" -ge "$_end" ] && break
    done
    echo "int_ops_per_sec=$(( _n * 100 / (NOW - _start) ))"
}

bench_flt() {
    # awk reads the clock itself, so its own startup is outside the timing.
    awk -v cs="$BENCH_CS" -v uptime="$BENCH_UPTIME" '
        function now(  line, f) {
            getline line < uptime
            close(uptime)
            split(line, f, " ")
            return f[1] + 0
        }
        BEGIN {
            x = 1.0
            n = 0
            t0 = now()
            while (1) {
                for (i = 0; i < 10000; i++)
                    x = x * 0.9999999 + 0.0000001
                n += 10000
                t = now()
                if ((t - t0) * 100 >= cs)
                    break
            }
            printf "flt_ops_per_sec=%d\n", n / (t - t0)
        }'
}

# DD_CS <- centiseconds one `dd` of $2 blocks of $1 bytes took.
# DD_BYTES <- bytes it actually copied, read from dd's own report rather than
# assumed: a read from /dev/zero may come back short, and a short read is still
# a record.
dd_time() {
    now_cs
    _t0=$NOW
    _report=$(dd if=/dev/zero of=/dev/null bs="$1" count="$2" 2>&1) || return 1
    now_cs
    DD_CS=$(( NOW - _t0 ))
    DD_BYTES=$(echo "$_report" | awk '/bytes/ { print $1; exit }')
    [ -n "$DD_BYTES" ]
}

bench_mem() {
    _ws=$1
    _c=1
    while :; do
        dd_time "$_ws" "$_c" || { echo "skipped mem_bandwidth_bytes_per_sec: dd bs=$_ws failed"; return; }
        _cs1=$DD_CS
        _b1=$DD_BYTES
        dd_time "$_ws" $(( _c * 2 )) || { echo "skipped mem_bandwidth_bytes_per_sec: dd bs=$_ws failed"; return; }
        _dcs=$(( DD_CS - _cs1 ))
        _db=$(( DD_BYTES - _b1 ))
        # Half the budget is enough here: the difference of two runs is what is
        # timed, and each doubling of c doubles the cost of the next attempt.
        if [ "$_dcs" -ge $(( BENCH_CS / 2 )) ] && [ "$_db" -gt 0 ]; then
            break
        fi
        _c=$(( _c * 2 ))
    done
    echo "mem_bandwidth_bytes_per_sec=$(( _db * 100 / _dcs ))"
    echo "mem_bandwidth_working_set_bytes=$_ws"
}

bench_sha256() {
    _file="$BENCH_TMP/bench-sha256-input.$$"
    # 64 bytes: one SHA-256 block of payload, so a digest is a digest and not a
    # measure of how fast a file is read.
    printf '%064d' 0 > "$_file" || { echo "skipped sha256_hashes_per_sec: cannot write $_file"; return; }
    _args=""
    _i=0
    while [ $_i -lt 256 ]; do
        _args="$_args $_file"
        _i=$(( _i + 1 ))
    done
    _n=0
    now_cs
    _start=$NOW
    _end=$(( _start + BENCH_CS ))
    while :; do
        # shellcheck disable=SC2086 -- the 256 copies are meant to split.
        sha256sum $_args > /dev/null || { rm -f "$_file"; echo "skipped sha256_hashes_per_sec: sha256sum failed"; return; }
        _n=$(( _n + 256 ))
        now_cs
        [ "$NOW" -ge "$_end" ] && break
    done
    rm -f "$_file"
    echo "sha256_hashes_per_sec=$(( _n * 100 / (NOW - _start) ))"
}

# Celaut's canonical tag for the architecture the measurement ran under, which
# is what the node files the scores under.
architecture() {
    case "$(uname -m)" in
        x86_64|amd64) echo "linux/amd64" ;;
        aarch64|arm64) echo "linux/arm64" ;;
        *) echo "linux/$(uname -m)" ;;
    esac
}

# WORKING_SET <- the working set a caller asked for, or the pinned default when
# it asked for none. Returns 1 with WORKING_SET_ERROR set when the value is not
# a plain decimal integer, is under 1 MiB (a buffer that small is a cache
# benchmark, and dd's own overhead swamps it), or would not fit in 3/4 of the
# memory available right now (dd allocates the whole buffer at once, and an
# out-of-memory kill would answer the caller with nothing at all).
parse_working_set() {
    WORKING_SET=${1:-$DEFAULT_WORKING_SET_BYTES}
    WORKING_SET_ERROR=""
    case "$WORKING_SET" in
        ''|*[!0-9]*|0*)
            WORKING_SET_ERROR="working_set_bytes must be a positive decimal integer, got '$WORKING_SET'"
            return 1 ;;
    esac
    # 18 digits always fit the shell's signed 64-bit arithmetic; anything longer
    # cannot be a size this machine has.
    if [ ${#WORKING_SET} -gt 18 ]; then
        WORKING_SET_ERROR="working_set_bytes $WORKING_SET is larger than this machine's memory"
        return 1
    fi
    if [ "$WORKING_SET" -lt 1048576 ]; then
        WORKING_SET_ERROR="working_set_bytes must be at least 1048576 (1 MiB), got $WORKING_SET"
        return 1
    fi
    _avail_kb=$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo 2>/dev/null)
    if [ -n "$_avail_kb" ] && [ "$WORKING_SET" -gt $(( _avail_kb * 1024 / 4 * 3 )) ]; then
        WORKING_SET_ERROR="working_set_bytes $WORKING_SET does not fit in 3/4 of the $(( _avail_kb * 1024 )) bytes available"
        return 1
    fi
    return 0
}

# The `key=value` / `skipped ...` lines on stdin as one JSON object: integers
# as numbers, `architecture` as a string, every `skipped` line in a list.
render_json() {
    awk '
        BEGIN { out = ""; skipped = "" }
        /^skipped / {
            sub(/^skipped /, "")
            gsub(/\\/, "\\\\"); gsub(/"/, "\\\"")
            skipped = skipped (skipped == "" ? "" : ",") "\"" $0 "\""
            next
        }
        /^[a-z0-9_]+=/ {
            key = substr($0, 1, index($0, "=") - 1)
            value = substr($0, index($0, "=") + 1)
            if (key == "architecture")
                value = "\"" value "\""
            else if (value !~ /^[0-9]+$/)
                next
            out = out (out == "" ? "" : ",") "\"" key "\":" value
        }
        END { printf "{%s%s\"skipped\":[%s]}\n", out, (out == "" ? "" : ","), skipped }'
}

run_all() {
    if ! [ -r "$BENCH_UPTIME" ]; then
        echo "skipped all: $BENCH_UPTIME is not readable"
        return 1
    fi
    parse_working_set "$1" || { echo "skipped all: $WORKING_SET_ERROR"; return 1; }
    echo "architecture=$(architecture)"
    bench_int
    bench_flt
    bench_mem "$WORKING_SET"
    bench_sha256
}

# Sourced with BENCH_LIB=1 (by the CGI and the tests), only define the functions.
if [ "${BENCH_LIB:-0}" != 1 ]; then
    run_all "$@"
fi
