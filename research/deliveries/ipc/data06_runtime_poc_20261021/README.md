# DATA-06 component source PoC and fix replay (2026-10-21)

## Mainline replay update

This delivery was checked against the locally available `origin/main` object
`b957894ca0229d7a6b0557b87d35e1c2ac877b07` (tree
`a8e1ca39deb827e253b6fe9f86679a1dc1ede2a5`) and the actual tip of
`origin/codex/b-ipc-closeout-20261020`, `96cfc453c15263ec3ec83ce87aa75d08d221b445`
(tree `e413abe82124654ffdd93b5bba82db407280ea9f`). They diverge after merge
base `4b0e16576a45a111b4fad7e8f82819a47ed472f5` (mainline 7 commits ahead,
B closeout 6 commits ahead). The DATA-06 detector, helper, family registration,
and IPC model blobs are identical at those two revisions. The B branch adds the
DATA-06 PoC/replay and its evidence package. Its other direct code differences
are eight shared-file edits that remove current-mainline known-CVE evidence
fields and their UI/API display; those edits are not needed here and were not
carried forward. A network fetch of GitHub was unavailable during this replay,
so “latest mainline” means the current local `origin/main` tracking object.
The compared commits and exact DATA-06 scanner blobs are captured in
`source_bindings.json`.

The mainline integration now attaches a traceable candidate-source assessment
to DATA-06 details and keeps the finding at candidate/unknown. Its
`CVE-2025-26474` association comes from the existing T74 regression manifest;
the NVD disclosure does not establish this allocation-width primitive as that
CVE's root cause. The mapping is provenance only. The detail view shows this
caveat, pinned upstream file/function/line range, vulnerable and fixed source
commits, PoC entrypoint and hashes, remediation, and source-semantic recheck
results.

The isolated workbench API replay is stored under
`artifacts/workbench_api_replay/`: it includes the candidate detail JSON,
immutable vulnerable/fixed static reports, and a summary with source, report,
and detail hashes. That run used exact source bytes from the two official
communication_ipc Git commits in a separate temporary Git repository, a
temporary database, and the finding-detail API. The visible panel consumes
that same finding-detail response. No shared service or data directory was
used.

## Result

The chosen path is OpenHarmony `communication_ipc`'s Cangjie FFI reader
`MessageSequenceImpl::CJ_ReadRemoteObjectArray` in
`interfaces/innerkits/cj/src/message_sequence_impl.cpp`. The primary source
revision is `84d681288793785e8f39f71c824f211edaed8f1e`, the vulnerable parent
of official fix `de3a68cc8b7d6f18017fd261060def0e38dce54a`. The same function
was independently present in the DATA-06 candidate revision
`67cd9d3e8e08971ba614a19f99b5f6b7ec4ea039`. Exact source commits, trees, blob
IDs, byte hashes, and scanner mainline blobs are in `source_bindings.json`.
The branch comparison and this local scan-to-detail delivery are summarized in
[`DATA06_MAINLINE_DEMO_20261021.md`](../DATA06_MAINLINE_DEMO_20261021.md).
The fetched B closeout branch was `codex/b-ipc-closeout-20261020` at
`24f80704d244d2ddf665fd50d9dfffeb448e9a87`; scanner `origin/main` was
`c380a474718e8ec4497aff55b18a1dd38bafa13f` (tree
`5c1e48e12f5d12fc7e350833267b438be3f35843`). The IPC detector, rule helper,
family entry, and model files have identical blobs on those two scanner
revisions.

Pinned-source anchors:

- Vulnerable method: `message_sequence_impl.cpp:1188`.
- Parcel count read: `:1195`; `CheckReadLength` call and under-sized
  allocations: `:1199-1205`; loop and indexed stores: `:1211-1218`.
- `CheckReadLength` implementation: `message_sequence_impl.cpp:787`.
- FFI export: `ipc_ffi.h:97`; handle lookup and forwarding call:
  `ipc_ffi.cpp:1142-1152`.
- Conditional shared-library target and relevant source list:
  `BUILD.gn:20-55` (`support_jsapi`).
- Official fix changes the two allocation expressions at
  `message_sequence_impl.cpp:1200,1205`.

At the candidate revisions, the function reads a positive `int32_t` count
from `nativeParcel_->ReadInt32()`, checks that the Parcel has at least
`count * BYTE_SIZE_32` remaining bytes, then allocates `int32_t* type` and
`int64_t* id` with `malloc(count)`. Its loop runs `count` times and writes
`type[i]` and `id[i]`. The output allocations are therefore `count` bytes,
while the loop writes `4 * count` and `8 * count` bytes respectively. For
count 4, the model allocates 4 bytes for each output and attempts 16 and 32
bytes of typed stores.

The source fix changes both allocations to
`malloc(sizeof(element_type) * arrayLength)`. The same fix also handles a null
remote-object read and sets `res.len`; those adjacent changes are not needed
to establish the allocation-width issue.

## Input, FFI, and trust boundary

The count originates in the Parcel, not a locally derived vector length.
`FfiRpcMessageSequenceImplReadRemoteObjectArray(int64_t id, int32_t* errCode)`
is declared with `FFI_EXPORT` in `interfaces/innerkits/cj/include/ipc_ffi.h`.
Its implementation resolves `FFIData<MessageSequenceImpl>` by `id` and calls
the vulnerable method. The IPC component's `interfaces/innerkits/cj/BUILD.gn`
defines the `cj_ipc_ffi` shared library when `support_jsapi` is enabled and
includes both implementation files. The method itself has no caller identity
or permission check.

This traces a C ABI/FFI bridge to the candidate method, but not a complete
deployed attacker route. The Cangjie caller that supplies a live sequence
handle, the service that hands it attacker-influenced Parcel data, product
build inclusion, and any service-level permission checks remain unknown.
`CheckReadLength` verifies input Parcel byte availability only; it does not
size the separate `type` and `id` output allocations. The count's upper bound
is indirectly constrained by Parcel remaining bytes; no explicit output
allocation-size guard exists in this method.

The T74 regression manifest associates the two source revisions with
`CVE-2025-26474` as one deduplicated root. The public vendor/NVD entry describes
a local, restricted-scenario input-validation issue but does not identify this
allocation-width primitive. This report therefore records the repository's
existing mapping as provenance only; it does not claim that this PoC validates
the CVE's published product impact or affected release. See the [official
vulnerable source](https://gitee.com/openharmony/communication_ipc/blob/84d681288793785e8f39f71c824f211edaed8f1e/interfaces/innerkits/cj/src/message_sequence_impl.cpp),
[official fix](https://gitee.com/openharmony/communication_ipc/blob/de3a68cc8b7d6f18017fd261060def0e38dce54a/interfaces/innerkits/cj/src/message_sequence_impl.cpp),
and [NVD CVE record](https://nvd.nist.gov/vuln/detail/cve-2025-26474).

## Isolated PoC

`array_width_poc.cpp` is a small deterministic semantic harness copied from
the pinned allocation, count-check, loop, and typed-store expressions. It
uses a fake Parcel returning valid non-null objects and does **not** compile
the OpenHarmony component or call Binder/DBinder. Its purpose is to test the
source-level allocation invariant, not product reachability or exploitability.
`run.sh` compiles both vulnerable and repaired allocation variants with
Clang/AddressSanitizer in WSL2 and preserves stdout/stderr and a result JSON in
`artifacts/`.
ASan's exact vulnerable stderr is preserved losslessly as
`artifacts/vulnerable.stderr.raw.b64`; its decoded byte count and SHA-256 are
recorded in `artifacts/result.json`. The adjacent `.txt` file is a readable
copy with trailing horizontal whitespace removed.

Executed command:

```sh
cd research/deliveries/ipc/data06_runtime_poc_20261021
bash run.sh
```

Observed results:

| Case | Result |
|---|---|
| Vulnerable allocation, count 4, sufficient Parcel bytes | ASan reports an 8-byte `id[0]` write into a 4-byte allocation |
| Fixed allocation, count 4 | Clean return |
| Vulnerable allocation, count 0 | Clean early return |
| Vulnerable allocation, count 4, only 2 Parcel bytes | `CheckReadLength` rejects; no overflow |

The ASan positive demonstrates an out-of-bounds write in this source-semantic
model. It does not show the write in the official component binary, establish
remote reachability, or show a product-level CIA consequence.

## Detector and regression evidence

The detector identity is `ohscanner.interface.ipc@0.12.13`, model
`oh-ipc-2026.10-v33`, family DATA-06, rule
`ipc.parcel.array-allocation-width@0.1.0`, source CWE-131, possible
consequence CWE-787. The model/rule source is bound to the exact fetched
scanner mainline and B-closeout commits in `source_bindings.json`. The existing T74
integration challenge verifies exact raw source hashes for two vulnerable
official revisions, one official fix, and safe, unrelated, wrong-repository,
check-only, and comment-only controls.

Validation on this checkout:

- Focused DATA-06 and T74 suite: **44 passed, 576 subtests passed**.
- IPC regression set (`tests/test_ipc*.py`): **423 passed, 1 skipped,
  712 subtests passed**.
- Isolated workbench scan → finding detail API → official fixed-source replay:
  **1 passed**; the candidate and fixed reports are retained under
  `artifacts/workbench_api_replay/`.
- Focused DATA-06/T74 test log: `artifacts/focused_pytest.log.txt`.
- Full IPC regression log: `artifacts/ipc_pytest.log.txt`.
- ASan vulnerable/fixed/negative raw output: `artifacts/`.

The skipped tests remain skipped; the 47 skips do not count as passes.

## Risk and disposition

**Disposition: source-level allocation-width candidate.** The pinned source
uses element counts as byte counts and its loop stores typed elements into
those allocations; the isolated ASan model reproduces the resulting
out-of-bounds write. The official source fix and exact-source detector replay
corroborate the source change. No CVSS or product severity is assigned because
remote reachability, required valid Parcel contents, and process impact are
unverified.

Unresolved: actual FFI caller reachability from an untrusted Cangjie caller;
whether remote-controlled Parcels containing the required valid remote-object
entries can reach this method in a shipped product; product/source build
inclusion; architecture/build flags; behavior in the full component binary;
and process-level confidentiality, integrity, or availability impact. Keep
the finding `candidate/unknown`, not product `confirmed`.

## Reproduction and provenance

1. Clone or use the official source Git repository and verify the commit/tree
   and `source_bindings.json` blob/hash values.
2. Replay the detector with the repository's pinned DATA-06 integration test:

   ```powershell
   $env:T74_IPC_GIT = '<official communication_ipc Git checkout>'
   python -m pytest -q tests/test_ipc_t74_cj_array_bounds_integration_challenge.py `
     tests/test_ipc_family_depth.py tests/test_ipc_family_matrix.py `
     tests/test_ipc_rule_versions.py tests/test_ipc_holdout_contract.py
   ```

3. Run the isolated ASan harness using `bash run.sh` in WSL2 or another
   Clang/ASan Linux environment.
4. Re-run the isolated workbench/API integration path from WSL2:

   ```sh
   python3 -m pip install --target /tmp/ohscanner-data06-deps pytest \
     -r requirements-web.txt
   PYTHONPATH=/tmp/ohscanner-data06-deps \
   T74_IPC_GIT=/path/to/communication_ipc \
   DATA06_DEMO_OUTPUT_DIR="$PWD/research/deliveries/ipc/data06_runtime_poc_20261021/artifacts/workbench_api_replay" \
   python3 -m pytest -q tests/test_workbench.py \
     -k data06_source_candidate_and_fixed_retest_reach_finding_detail_api
   ```

   This API test creates its own temporary target repository and workbench
   data directory. It does not start or modify the shared 8765 service.

The official source repo was fetched from
`https://gitee.com/openharmony/communication_ipc.git`. No product image,
service, device, or live IPC endpoint was used. No holdout metric or
independent accuracy claim is made.
