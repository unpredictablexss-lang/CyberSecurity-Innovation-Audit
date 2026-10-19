# T5 independent D5 intake gate review

Date: 2026-10-20. Scope: synthetic structural intake gate only. T5 did not fill real product fields, authenticate an issuer, verify evidence meaning/custody, or establish IBS5YG product inclusion.

## Reviewed commits and artifacts

- T5 base: `7b4e6478043b4f26791aa84781093dd965540c9e`.
- D5 first reviewed commit: `67bc597cc415c0ea1f0de3cc12a9b8a4fd651e3c`.
- D5 repaired commit independently re-tested: `8f176b7a5d35b58050ff1a062424ea4b5205f151`.
- Repaired D5 validator SHA-256: `1cf554323b891c8921111abb44d9cd6993482c3f267080fd5439ff62031771e6`.
- D5 schema SHA-256: `4097a771d295137ffd85f873206133fe549b83cfab8cb6821fb04bfc5ee72b79`.
- Repaired D5 self-test output: `d5-selftest-8f176b7a5d35b58050ff1a062424ea4b5205f151.json`, SHA-256 `ae3f96333a1da2a8d82d1032765c1bb417a06903b702cc3f8205eed64ee21951`.
- T5 black-box output against repaired D5: `blackbox-8f176b7a5d35b58050ff1a062424ea4b5205f151.json`, SHA-256 `dbffd273a361394e14da8d6f6a5864522e6779b123ac398665776eb30328a728`.
- T5 case definitions: `cases.json`, SHA-256 `2040c81f4464450b044ddf2ae1f779f45be8bc663d8f8dc6097903af4ee94e92`.
- T5 runner: `run_blackbox.py`, SHA-256 `23d48dcadce37a3e003f2d440ee73d79c319f148babdf68f24c7315ecea5083b`.
- T5 preparation README: SHA-256 `31a8281e6e52bc9de621416d30ee20069e6ed950fab4adae6abf522158e0cbdc`.
- This review report SHA-256 is recorded in the final handoff after this document is committed.

## Initial counterexamples and D5 feedback loop

Against D5 `67bc597cc415c0ea1f0de3cc12a9b8a4fd651e3c`, the validator accepted a syntactically immutable HTTPS URI without binding its digest to the evidence bytes:

| Case | Input SHA-256 | Observed result on first D5 commit | Required behavior |
|---|---|---|---|
| URI digest differs from referenced manifest bytes | `559b7718b420e11033ec6da42691b1a2bcf9f101cf928366a7a2f0db898311af` | Exit 0, `STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW`, `admission_ready=false` | Reject because URI digest does not equal the referenced manifest byte digest |
| URI points to nonexistent manifest and only carries a made-up digest | `5266e63dad9bdb5820a73b63da5095c9536ae7b165012849331575a47c5728bd` | Exit 0, `STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW`, `admission_ready=false` | Block because no local bytes substantiate the URI digest |

T5 sent the exact D5 SHA, validator hash, input hashes, and reproduction command to D5. D5 added local-byte digest binding for HTTPS manifests and local Git object resolution for commit references in `8f176b7a5d35b58050ff1a062424ea4b5205f151`. T5 then ran the same adversarial conditions against that exact repaired commit; both now return `WAITING_OR_BLOCKED` with `admission_ready=false`. A syntactically valid but nonexistent local commit is also blocked.

## Independent black-box results

The T5 runner invoked the D5 CLI as a subprocess, generated each input/evidence tree in a fresh temporary directory, and recorded the serialized intake SHA-256. The repaired D5 commit passed all 21 cases:

- Positive synthetic control: exit 0, status `STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW`, `admission_ready=false`.
- All-six-missing control and each of the six individual missing-field cases: exit 2, `WAITING_OR_BLOCKED`.
- Evidence bytes tampering / digest mismatch: blocked.
- Parent traversal, POSIX absolute path, Windows drive absolute path: blocked.
- Missing issuer field: blocked. A syntactically present but unverified issuer label can pass structural checks, as documented; issuer authenticity is not claimed.
- Conflicting build identity and mixed product/release binding: blocked.
- Caller-supplied `status=READY`: rejected as an unexpected input key.
- URI digest mismatch and unresolved URI: blocked.
- Fake 40-hex commit with no matching local Git object: blocked.
- Windows junction escape: created successfully on this host and blocked as a reparse-point path.

All case input hashes, exit codes, outputs, error codes, and structural-only limitations are in the black-box JSON artifact cited above. The D5 self-test passed all 14 checks. The Draft 2020-12 JSON Schema accepted the T5 positive control. The original blocked example returned exit 2, `WAITING_OR_BLOCKED`, and `admission_ready=false` for all six null fields.

## Reproduction commands

From the T5 worktree `D:\openHarmonyScanner\worktrees\c-t5-intake-gate-20261020`:

```powershell
python research\methods\ark_runtime\ibs5yg_profile_gap_20261020\review\intake\run_blackbox.py --validator D:\openHarmonyScanner\worktrees\c-d5-intake-gate-20261020\research\methods\ark_runtime\ibs5yg_profile_gap_20261020\intake\validate_intake.py
```

From the D5 worktree, at the reviewed repaired commit:

```powershell
python research\methods\ark_runtime\ibs5yg_profile_gap_20261020\intake\validate_intake.py --self-test
python research\methods\ark_runtime\ibs5yg_profile_gap_20261020\intake\validate_intake.py --manifest research\methods\ark_runtime\ibs5yg_profile_gap_20261020\intake\blocked-example.json --evidence-root research\methods\ark_runtime\ibs5yg_profile_gap_20261020\intake
```

The second command is expected to return exit code 2 for the blocked example.

## Scope and interpretation

Only structural shape, local evidence-byte hashing, safe path containment, declared identity consistency, manifest digest-to-local-byte equality, and local Git commit object correspondence were exercised. `STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW` is not `READY`: all positive controls explicitly returned `admission_ready=false`. No case proves a human issuer's identity or authority, claim sufficiency, acquisition/custody, release provenance, shipped product association, or vulnerability status. The real D5 intake still has six null minimum inputs and PC-1 remains blocked.

## Change-scope check

`python -m scripts.check_change_scope --base 7b4e6478043b4f26791aa84781093dd965540c9e --lane c_t5` returned `violations: []` and listed only the six files under the T5 allowlist. `git diff --check` returned success with no diagnostics. No file outside `research/methods/ark_runtime/ibs5yg_profile_gap_20261020/review/intake/**` was changed by this lane.
