# Vendor rules

Third-party Semgrep rules committed here so the historical benchmark can be
replayed without a live registry connection. Vendored rules are byte-for-byte
copies of the upstream files; only this README and the `.source_commit` pin are
ours.

## raptor/ — 0xdea/semgrep-rules (C/C++)

- Upstream: <https://github.com/0xdea/semgrep-rules>
- Pinned commit: see `raptor/.source_commit` (`dae50da6e6e629750f1daec73a01ef9206a372ab`)
- License: MIT, Copyright (c) 2022 raptor — see `raptor/LICENSE`
- Content: 49 rules in `rules/c/` (ids prefixed `raptor-`), targeting C and C++.
- Why this source: it is the de-facto community C/C++ Semgrep ruleset
  (vulnerability-research oriented) and is the only maintained public option
  that actually declares `languages: [c, cpp]`.

Refresh:

```sh
git clone --depth 1 https://github.com/0xdea/semgrep-rules.git
cp 0xdea-semgrep-rules/rules/c/*.yaml rules/cpp/vendor/raptor/
cp 0xdea-semgrep-rules/LICENSE       rules/cpp/vendor/raptor/LICENSE
(cd 0xdea-semgrep-rules && git rev-parse HEAD) > rules/cpp/vendor/raptor/.source_commit
```

## Why the official Semgrep registry is only used for C

Verified 2026-10-06 with Semgrep 1.179.0 and the public registry API:

- `--config p/cpp` → HTTP 404; `--config r/cpp` → empty ruleset.
- The registry exposes 154 `cpp.*` rules, but **all of them are `team_tier`
  (pro) rules** and require a paid account / `SEMGREP_APP_TOKEN`.
- The free registry's C++ coverage is effectively zero: `p/default` (1073 rules)
  and `p/security-audit` (225 rules) contain **0** `cpp` rules.
- Official `c.lang.*` public rules number 16 and declare `languages: [c]` only,
  so Semgrep will not run them against `.cpp`/`.hpp` files.
- `semgrep/semgrep-rules` (the official repo backing the registry) has no `cpp/`
  directory and never had one.

Consequences for this benchmark:

- For C files (`.c`) and C headers (`.h`): use the official registry, e.g.
  `--config p/security-audit` or the 16 public `c.lang.*` rules.
- For C++ files (`.cpp`): the free registry has nothing, so the raptor set above
  plus the OpenHarmony-specific rules in `rules/cpp/` carry C++ coverage.
- C++ null-deref / lifetime pro rules exist (`cpp.lang.security.memory.*`) but
  are paywalled; do not silently substitute generic rules for them.
