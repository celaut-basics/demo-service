# nodo_protos

`celaut.binpb` is a copy of `protos/celaut_doc.binpb` from
[celaut-project/nodo](https://github.com/celaut-project/nodo) at commit
`ec390b90` (branch `feat/636-price-bounded-volatility`, PR
[#637](https://github.com/celaut-project/nodo/pull/637), 2026-11-09). It is a
`FileDescriptorSet` of `celaut.proto`. Since #538 it has `Service.Workload`,
`Service.Group`, `Service.Clause` and `Service.initial_environment_workload` (6).
Since #636 `EstimatedCost` has `price_bounded` (5), `price_volatility` (6) and
`volatility_period_seconds` (7), and `cost` is what the start spends: the build and the
builds of the initial children, with no balance. A client funds a start with `cost` plus
the funding sum of the periods that it chooses (`nodo_gateway.funding_sum_mu`).

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
