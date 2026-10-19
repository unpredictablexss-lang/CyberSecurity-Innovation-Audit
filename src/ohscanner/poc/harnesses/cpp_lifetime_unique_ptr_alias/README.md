# unique_ptr raw-alias lifetime PoC

This controlled ASan workload covers the detector's expanded invalidation
boundaries: `reset`, owner null assignment, owner replacement and `std::move`
transfer. It also revalidates two controls: unconditional alias rebinding and
use-before-reset.

Run:

```bash
.venv-web/bin/python -m src.ohscanner.poc.cpp_lifetime_uaf \
  --output outputs/poc/cpp-lifetime-unique-ptr-alias-20261014/run-001
```

The harness is self-authored and hash-bound. Results remain
`candidate/unassessed`, `validated_vulnerability=0`, and do not establish real
product reachability, attacker control, security impact or exploitability.