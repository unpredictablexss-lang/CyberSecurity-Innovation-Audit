# DATA-06 candidate evidence

> Source-level candidate only. The CVE association is provenance, not root-cause proof.

- Candidate report SHA-256: `761956f62459167b8dbafa214e175dcd8561d827e5c51d2b02824bf58d406183`
- Candidate: `ipc.parcel.array-allocation-width` at `interfaces/innerkits/cj/src/message_sequence_impl.cpp:1188`
- Source SHA-256: `1f4d039b974a0021000126e61efea7eb0b8eb5f4baf756373c1b12150d0d5eec`
- Source location: `MessageSequenceImpl::CJ_ReadRemoteObjectArray`, `interfaces/innerkits/cj/src/message_sequence_impl.cpp:1188-1218`
- Vulnerable source commit: `84d681288793785e8f39f71c824f211edaed8f1e`
- CVE mapping: CVE-2025-26474 (候选映射；非根因证明)
- Mapping basis: T74 regression manifest associates this source root with CVE-2025-26474. The public disclosure describes an input-validation issue but does not establish this allocation-width primitive as its root cause. Treat the CVE link as provenance only.
- Mapping source: https://nvd.nist.gov/vuln/detail/CVE-2025-26474
- Severity / product applicability: `unknown` / `unknown`
- Disposition: `candidate/unknown`; no product confirmation.

## Component-level PoC and fix comparison

- PoC scope: isolated source-semantic ASan harness; OpenHarmony component not compiled
- Harness entry: MessageSequenceImpl::CJ_ReadRemoteObjectArray allocation/count/typed-store semantics; count=4
- PoC record: `research/deliveries/ipc/data06_runtime_poc_20261021/README.md` (SHA-256 `eddf6ba05843a7888f89c138be720841790a4ee99367f7b0a433255019ae3209`)
- Replay command: `research/deliveries/ipc/data06_runtime_poc_20261021/run.sh` (SHA-256 `7994b7e0ca6d404ba64292014df567eddd51b3fd2bd23d793a9cceacff154209`)
- Raw ASan output: `research/deliveries/ipc/data06_runtime_poc_20261021/artifacts/vulnerable.stderr.raw.b64` (decoded SHA-256 `b27931bbf0ae57391ae40046f5a8c0899a8f49f357a5caeecd9e35630fd6747b`)
- Fixed source: `de3a68cc8b7d6f18017fd261060def0e38dce54a`; Allocate sizeof(element_type) * arrayLength; upstream fixed source is the recorded commit.
- Upstream fix: https://gitee.com/openharmony/communication_ipc/commit/de3a68cc8b7d6f18017fd261060def0e38dce54a
- Vulnerable replay: ASan heap-buffer-overflow in source-semantic harness at count=4.
- Fixed replay: Clean return in source-semantic harness at count=4.
- Exact-source retest: Pinned official source fix de3a68cc8b7d6f18017fd261060def0e38dce54a; detector replay expects zero DATA-06 finding.

## Limits

- The harness does not compile the OpenHarmony component and does not establish Binder/DBinder reachability, shipped build inclusion, or product impact.
- Source-semantic harness and exact-source detector replay; no OpenHarmony binary, Binder/DBinder reachability, or product impact verified.
- No real IPC or FFI reachability or product impact was established; no OpenHarmony component build was produced.
- The API replay wraps pinned official source bytes in temporary local Git commits; those wrapper commits are not OpenHarmony release identifiers.
