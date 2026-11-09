# nodo_protos

`celaut.binpb` is a copy of `protos/celaut_doc.binpb` from
[celaut-project/nodo](https://github.com/celaut-project/nodo) at commit
`8fcaf618` (branch `feat/538-cnf-workloads`, PR
[#635](https://github.com/celaut-project/nodo/pull/635), 2026-11-09). It is a
`FileDescriptorSet` of `celaut.proto`. Since #538 it has `Service.Workload`,
`Service.Group`, `Service.Clause` and `Service.initial_environment_workload` (6).
`EstimatedCost` has no `children_initial_cost` any more (field 6 is reserved): `cost`
includes the starts of the initial children, as `initial_children_cost` checks.

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
