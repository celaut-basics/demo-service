# nodo_protos

`celaut.binpb` is a copy of `protos/celaut_doc.binpb` from
[celaut-project/nodo](https://github.com/celaut-project/nodo) at commit
`a97148dd` (dev, 2026-11-08). It is a `FileDescriptorSet` of `celaut.proto`.

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
