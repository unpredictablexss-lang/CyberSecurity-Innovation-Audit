# DelayedSingleton shared_ptr race PoC

This family PoC compiles a self-authored workload against the preserved, hash-
verified `singleton.h` bytes for:

- vulnerable commit `bdfafdaafddb01ab7ae13354ce2ada9555d7935c`;
- upstream fix commit `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7`;
- a locally derived fully-atomic patch used for remediation revalidation.

The current local target Git store does not contain those historical objects, so
Git-object provenance remains unknown. The runner refuses hash or required-quote
mismatches and records that limitation instead of upgrading provenance.

Run:

```bash
.venv-web/bin/python -m src.ohscanner.poc.cpp_shared_ptr_race \
  --output outputs/poc/shared-ptr-delayed-singleton-20261014
```

The workload runs a single-thread control and repeated reader/destroyer races
under ThreadSanitizer. The result remains `candidate/unassessed` with
`validated_vulnerability=0`: component-level dynamic evidence does not prove
product reachability, attacker control, CIA impact or exploitability.