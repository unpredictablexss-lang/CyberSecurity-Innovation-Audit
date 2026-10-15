# A-line C/C++ detector close-out evidence checklist

Date: 2026-10-15 (Asia/Shanghai)

Scope: `shared_ptr` `0.5.0` and lifetime `0.4.0` implementation close-out only.
The public `contracts` / `runner` / `catalog` / `registry` surface is unchanged.
The dirty worktree and generated evidence are preserved; no historical report, candidate ID,
review or baseline control manifest is rewritten.

## Identity and package separation

- [x] Checkout: branch `codex/full-runtime-performance-audit-20261014`, remote
      `https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`.
- [x] HEAD `0dd71fd78baa01283df081f9bd02fe4b7f2df326`; HEAD tree
      `20ec92e835803f486d088eef183c7db08564926b`.
- [x] Implementation remains an uncommitted dirty-worktree source-hash binding; no commit is claimed.
- [x] Historical baseline `research/tests/cpp_detector_controls/manifest.json` remains separate and
      unchanged, SHA-256 `8065687ef494a26762af05c3e91828648365a88205481e41d5cf78088f23e9f2`
      (`shared_ptr 0.4.0`, lifetime `0.3.0`).
- [x] Current implementation-bound package is
      `research/tests/cpp_detector_controls_impl_20261015/manifest.json`, SHA-256
      `b12711b567fa59c2b562fa1f353fd1bd1ee31d2780ad6f6cb597e4e9cb70eb3a`
      (`shared_ptr 0.5.0`, lifetime `0.4.0`).

## Per-control execution record

`research/evidence/cpp/implementation_bound_controls_20261015/run-002/results.json`
(SHA-256 `2be497117214f5dd060d3e4f15cf68d3ebecdc025a3c03ee6ee3af4dff7345cc`)
contains 20 control records. Tests assert every record has:

- [x] exact build `argv` and exact per-repeat run `argv`;
- [x] compiler identity (`clang++`, Ubuntu clang 14.0.0) and sanitizer (`thread` or `address`);
- [x] repeat index and repeat count (`3`);
- [x] source SHA-256, binary SHA-256 and build/run log SHA-256;
- [x] expected result, observed result, pass/fail status and failure list.

The replay passed 20/20 detector controls, 20/20 native controls and 60/60 native runs:
7 vulnerable, 6 fixed, 5 safe and 2 unrelated controls. All 21 vulnerable runs were
sanitizer-triggered; all 39 fixed/safe/unrelated runs were clean. Six authored remediation
patches applied with `patch -p1 --fuzz=0 --batch` and produced byte-identical fixed sources.

- [x] `execution.json`: SHA-256 `cb5405b8f32695b8db4c77348ebaf9a399953be23b0890177bab21f477d37f24`.
- [x] `verification.json`: SHA-256 `8255057dff0ca43caae2208b78f837bd4f832f20a3ffe56d08d253a9a3c46682`.
- [x] `SHA256SUMS.txt`: SHA-256 `5d39fdc08f89f00345240cc54433557176b3c7b78e90920c36e10c94c05b6a46`.
- [x] `work_binaries.sha256`: SHA-256 `6c86baf4ab2c6ab81ebbc149d62083cbc2d216608f5f56491976eb35cfbcfcae`
      for 29 built control/PoC binaries.

## PoC manifests and controlled reruns

- [x] DelayedSingleton manifest:
      `src/ohscanner/poc/harnesses/cpp_shared_ptr_delayed_singleton/manifest.json`,
      SHA-256 `8dc2e5d151c038e8e9416f6083e0ae89757e7ae54b3698ca57fd447ff6b266b5`.
      It binds `harness.cpp` and `nocopyable.h`, canonical argv, `clang++`, ThreadSanitizer,
      three repeats, environment and required result fields.
- [x] unique_ptr/raw-alias manifest:
      `src/ohscanner/poc/harnesses/cpp_lifetime_unique_ptr_alias/manifest.json`,
      SHA-256 `efba48f1080f54c66be61978e515f86b26e8fa9de46976a7bddc274697740285`.
      It binds `harness.cpp`, canonical argv, `clang++`, AddressSanitizer, three repeats,
      environment and required result fields.
- [x] DelayedSingleton controlled rerun:
      `run-002/family_poc/shared_ptr_delayed_singleton.json`, SHA-256
      `9271b75ce78be5df11f715081a57b99d47d366f9ce8e9bccc5aa693793367794`.
      Vulnerable and upstream-fix race modes triggered TSan 3/3; the fully-atomic local
      patch was clean 3/3; single-thread controls were clean.
- [x] unique_ptr/raw-alias controlled rerun:
      `run-002/family_poc/lifetime_unique_ptr_alias.json`, SHA-256
      `43076ca2ad15970acdd0d3544b44619f30d89293f5c4b7f08b8dbe18b2615b2c`.
      Four invalidation variants triggered ASan 3/3; `fixed_rebind` and
      `safe_use_before_reset` were clean 3/3.

## Method and regression records

- [x] `research/methods/cpp/SHARED_PTR_RACE_METHOD_CARD.md`, SHA-256
      `7c5144d533dcfab951a1e1bcdf86ee07fc090d8939fc35be5f4962e8885c8475`.
- [x] `research/methods/cpp/LIFETIME_METHOD_CARD.md`, SHA-256
      `97ab059d88db42658af024668916de647dfb1df51fb900cb66b304542d4651d3`.
- [x] `research/methods/cpp/DETECTOR_POC_MATRIX.md`, SHA-256
      `0f2a29313ec4845ce00ac5ce11375f11c9a4cb00d84cf9900e0cceaad4475449`.
- [x] `.venv-web/bin/python -m unittest discover -s tests -q`:
      577 executed, 569 passed, 8 skipped, 0 failed.
- [x] `git diff --check`: passed; Git only emitted line-ending normalization warnings.

## Interpretation boundary

- [x] Default status remains `candidate/unassessed`; `validated_vulnerability=0`.
- [x] Safe/unrelated zero findings are narrow negative controls only, not safety proof.
- [x] Fixed controls are authored remediation controls, not upstream product patches.
- [x] These synthetic controls are not independent labelled holdout data.
- [x] No Precision/Recall, zero-FP/FN, product reachability, attacker control, CIA impact,
      `confirmed` or `reportable` claim is made.
- [x] Shared_ptr historical Git-object provenance remains unknown. Lifetime CFG/exception/
      destructor/cross-function boundaries and real product entry/privilege/CIA impact remain unknown.