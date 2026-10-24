# nodo_protos

`celaut.binpb` is a copy of `protos/celaut_doc.binpb` from
[celaut-project/nodo](https://github.com/celaut-project/nodo) at commit
`97906c7c` (dev, 2026-10-24). It is a `FileDescriptorSet` of `celaut.proto`.

`nodo_gateway.py` loads it into a private descriptor pool. The pinned
`node_controller` keeps its own, older `celaut.proto` in the default pool, and
the newer benchmarks need messages it does not have: `StartReference` (#578),
`BalanceStatementRequest` and `BalanceStatement` (#570), and the current
`EstimatedCost` and `Peer`.

To update it, copy the file from the nodo commit that the benchmarks test:

```sh
cp <nodo checkout>/protos/celaut_doc.binpb nodo_protos/celaut.binpb
```

A change of the file changes the service id of the verifier.
