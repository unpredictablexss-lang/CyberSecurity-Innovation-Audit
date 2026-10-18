# A line: JSProxy::instance_ component case

Status: `candidate/unassessed`; component reproduction passed; product gate
`not_met`; `validated_vulnerability=0`.

## What was developed

- Bound `JSProxy::instance_` to
  `openharmony/distributeddatamgr_kv_store@acfb22aac16161d8fb0cefb6cc9b92f04f489a80`.
- Confirmed the existing `ohscanner.cpp.shared_ptr_race` 0.5.1 detector reports
  the `SetInstance` write and `GetInstance` read in `js_proxy.h`.
- Added an automated detector regression for the `JSProxy` set/get pair.
- Added a self-authored TSan harness for the pinned header bytes.
- Added a minimal `std::mutex` patch that locks both accessors.

## Reproduction

From the repository root in a Linux/WSL environment:

```text
python3 research/evidence/cpp/jsproxy_case_20261018/run_case.py
```

The script compiles vulnerable and fixed variants with clang++ 14 and runs each
three times. Expected result: vulnerable `66/66/66` with TSan data race; fixed
`0/0/0` with no race.

`python3 verify_case.py` re-checks the source/blob hashes, run outcomes, patch
hash and `git apply --cached --check`; the expected output is `case_ok`.

## Evidence

- `research/evidence/cpp/jsproxy_case_20261018/case_manifest.json`
- `research/evidence/cpp/jsproxy_case_20261018/results.json`
- `research/evidence/cpp/jsproxy_case_20261018/logs/`
- `research/evidence/cpp/jsproxy_case_20261018/patch/js_proxy_mutex.patch`

The patch applies to the pinned Git index:

```text
git apply --cached --check patch/js_proxy_mutex.patch
```

## Boundary

This package proves a component-level unsynchronized `shared_ptr` access pair
and a component-level mutex remediation. It does not prove a product build,
real entry, permission boundary, attacker control, CIA impact or product
exploitability. The detector candidate remains unassessed.
