# benchmark — per-core scores for a nodo node

The service a nodo node runs as its optional `benchmark` **core service**
([celaut-project/nodo#459](https://github.com/celaut-project/nodo/issues/459)).
It measures the four per-core primitives nodo's admission holds a service's
`resources.at_init.benchmark` requirement against, and returns them for the
architecture it ran under. The node writes them into its own `config.yaml`,
under that architecture.

It is also a dependency of the demo-service verifier (`BENCHMARK` in
`../<arch>/.service/pack_config.json`): packing the demo packs this too, and its probe
suite launches it like `tiny`/`heavy`/`ping` (`dependency_identity` and
`node_benchmark`, see `../VERIFIER.md`).

## API

Port 3030, HTTP, like the other variants.

| Request | Answer |
|---|---|
| `GET /cgi-bin/benchmark` | runs every benchmark over the pinned default working set |
| `GET /cgi-bin/benchmark?working_set_bytes=<n>` | same, over a working set of `n` bytes |
| `GET /cgi-bin/whoami` | `{"service":"benchmark","identity":"celaut-demo-benchmark","role":"node-benchmark"}` |

A run takes ~10 s natively and about as long again under QEMU+TCG (each primitive
runs for a fixed 2 s; only the memory one can take longer). The answer:

```json
{
  "architecture": "linux/amd64",
  "int_ops_per_sec": 78500,
  "flt_ops_per_sec": 250000,
  "mem_bandwidth_bytes_per_sec": 14810232055,
  "mem_bandwidth_working_set_bytes": 1073741824,
  "sha256_hashes_per_sec": 17024,
  "skipped": []
}
```

- Every score is **per core, per second**, an integer. A primitive that could not be
  measured is absent and its reason is in `skipped`: missing means unmeasured, never 0.
- `architecture` is Celaut's canonical tag for `uname -m`. The node files the scores
  under it, so an `amd64` build run under QEMU+TCG on an arm64 host reports
  `linux/amd64` with emulated numbers, which is exactly what that node offers for
  that architecture.
- `400` with `{"error": ...}` for a working set that is not a positive decimal, is
  under 1 MiB, or does not fit in 3/4 of the memory available. `409` while another
  run is in flight on the same instance: two concurrent runs would each measure half
  a machine.

## What each number is

| Key | Loop |
|---|---|
| `int_ops_per_sec` | ash integer LCG steps (`x = (x*1103515245 + 12345) & (2^31-1)`) |
| `flt_ops_per_sec` | awk floating-point multiply-adds (`x = x*0.9999999 + 0.0000001`) |
| `mem_bandwidth_bytes_per_sec` | bytes `dd if=/dev/zero of=/dev/null bs=<working set>` writes through its buffer per second |
| `mem_bandwidth_working_set_bytes` | the buffer size that bandwidth was measured over |
| `sha256_hashes_per_sec` | `sha256sum` digests of a 64-byte file, 256 files per process |

The design is the one nodo#457 ran inside the guest initramfs, ported as is:

- **Time comes from `/proc/uptime`**, read with the `read` builtin (no fork per
  reading). `"1${frac}" - 100` turns the fraction into centiseconds without the
  shell reading `.08` as an (invalid) octal literal.
- **One process per loop**, so a score is what one core does.
- **Memory over a working set larger than the LLC.** `dd` reuses one buffer of
  `bs` bytes, so `bs` *is* the working set. Its fault-in and dd's own startup are
  cancelled by timing `count=c` and `count=2c` and dividing the extra bytes by the
  extra time.
- **Many digests per `sha256sum` process**: one process per digest measures
  fork+exec, not SHA-256.

### The pinned working set: 1 GiB

`DEFAULT_WORKING_SET_BYTES=1073741824` in `bench.sh`, and nodo pins the same
number (`src/utils/benchmark.py`). A bandwidth is only comparable with another
one measured over the same amount of memory: 5 KiB lives in L1, and a node
reporting a small-set number would be reporting its cache. So the size always
travels with the score, and the default has to be:

- **larger than any last-level cache one core can use.** The largest unified
  LLCs shipping are ~0.5 GiB (Xeon 6980P, 504 MB). AMD's 3D V-Cache parts reach
  1 GiB+ in total, but split per CCD, ~96 MiB of it visible to one core.
  1 GiB is twice the largest.
- **well below the benchmark VM's RAM.** `service.json` declares 2 GiB, so
  `dd`'s 1 GiB buffer leaves ~1 GiB for the kernel, busybox and the page cache.

A caller can ask for another size. nodo accepts a score for a requirement only
when the score's working set is at least the requested one: a larger set can
only lower bandwidth, so it never flatters a node.

## Packing

```sh
nodo pack benchmark/arm64     # prints the linux/arm64 service id
nodo pack benchmark/amd64     # prints the linux/amd64 service id
```

**A service is one architecture**, so this one is kept twice: `arm64/.service/`
and `amd64/.service/`, each with its own `Dockerfile`, `service.json` and
`pack_config.json`, over the shared `bench.sh`/`serve`/`www` (linked into each).
A node that serves `linux/amd64` (natively, or under QEMU+TCG) needs the amd64
pack: same source, another id. Both Dockerfiles pin the busybox *index* digest,
so both packs take their image from the same pin. See "Packing: one tree per
architecture" in `../VERIFIER.md` for the layout.

Then, on the node (`config.yaml`):

```yaml
core_services:
  benchmark: "<id>"        # or a list, one id per architecture: ["<arm64 id>", "<amd64 id>"]
```

## Tests

```sh
python3 tests/test_benchmark.py
```

The clock, working-set and JSON helpers and the CGI's refusals run under any
POSIX `sh`. The measurement itself runs against the pinned busybox: the local
one on Linux, `docker run <pinned image>` elsewhere, skipped when neither is
there.
