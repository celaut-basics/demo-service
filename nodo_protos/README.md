# nodo_protos

`celaut.binpb` is a copy of `protos/celaut_doc.binpb` from
[celaut-project/nodo](https://github.com/celaut-project/nodo) at commit
`eda0a9b3` (branch `feat/538-cnf-workloads`, PR
[#635](https://github.com/celaut-project/nodo/pull/635), 2026-11-08). It is a
`FileDescriptorSet` of `celaut.proto`. Since #538 it has `Service.Workload`,
`Service.Group`, `Service.Clause`, `Service.initial_environment_workload` (6) and
`EstimatedCost.children_initial_cost` (6), which `children_initial_cost` and the funding of
the children read.

`nodo_gateway.py` loads it into a private descriptor pool, apart from the default pool of
protobuf. The `celaut` command does not read quotes, statements or tunnels, and the newer
benchmarks need messages for them: `StartReference` (#578),
`BalanceStatementRequest` and `BalanceStatement` (#570), and the current
`EstimatedCost` and `Peer`.

To update it, copy the file from the nodo commit that the benchmarks test:

```sh
cp <nodo checkout>/protos/celaut_doc.binpb nodo_protos/celaut.binpb
```

A change of the file changes the service id of the verifier.
