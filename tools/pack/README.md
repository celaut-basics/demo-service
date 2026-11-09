# tools/pack

Pack the verifier with every workload of `initial_environment_workload` and
`possible_environment_workload` named by the service id of its child (nodo #538).

```sh
tools/pack/pack.sh amd64 [stage dir]   # on a node with nodo #538, from the repository root
```

The node prices the build of an initial child only when the workload names it by hash, and
the ids of the children change with every pack. So `pack.sh`:

1. packs each child on its own (`nodo pack <child>/<arch> --local --json`);
2. stages a copy of `family/<arch>` with `stamp.py`: tiny's id in its workload and in its
   `pack_config.json`, then packs it;
3. stages a copy of `<arch>` the same way with every id, then packs it.

The ids go to `<stage dir>/ids.env` (`NAME=<id>` lines, `VERIFIER` last) and each pack log
to `<stage dir>/pack-*.log`. The copies take each child from the registry by its id, so a
child is packed once. `workload_children.json` says which dependency each workload is, in
the order of the clauses, groups and workloads of each `service.json`; keep the two in step
(`tests/test_initial_children_cost.py` checks it). `nodo pack` packs one service at a time
on a node; arm64 needs `packer.ARM_PACKER_SUPPORT: true` (and binfmt on an amd64 host).
