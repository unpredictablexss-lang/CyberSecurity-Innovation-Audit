# cpp.lifetime native evidence note: 2026-10-10

Status: `candidate/unassessed/draft` research evidence. This note records scoped
execution and method-compatibility facts, not vulnerability or safety verdicts.

## Identity and commands

- Repository: `openharmony/commonlibrary_c_utils`
- Sample: `c_utils-singleton-uaf-2026-01`
- Root-cause instance: `c_utils-singleton-uaf-2026-01`
- Detector: `ohscanner.cpp.lifetime`, `0.2.0-proposed`
- Rule: `ohcpp-lifetime-unique-raw-alias-reset-001`
- Profile: `light-ast`; no external scanner or query was invoked
- Python: 3.12.14 on Windows 11

Commands:

~~~text
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m research.experiments.cpp.native_lifetime_replay_2026_10_10 --write
C:\Users\work_work\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -m research.experiments.cpp.native_lifetime_replay_2026_10_10 --check
~~~

Each cell was executed independently through the script's hidden
`--emit-run <run-spec>` child command. Vulnerable, fixed and safe did not
substitute for one another.

## Per-control results and hashes

| Role | Commit | Analysis unit | Input/source SHA-256 | Config SHA-256 | Elapsed | Execution / failure | Benchmark result |
|---|---|---|---|---|---:|---|---|
| vulnerable | `bdfafdaafddb01ab7ae13354ce2ada9555d7935c` | `DelayedSingleton` pair | `ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4` | `c91e447acb8004a54fa9324a8a6f5481f9a085471ba6e0829af8bde5d3c986c9` | 0.130348 s | `blocked` / `blocked` | `not_applicable` |
| fixed | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `DelayedSingleton` pair | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` | `47297005613ad5ce5158bc6492ff9fd168c1daae50e3a8115211ca900482efa9` | 0.129106 s | `completed` / `none` | `not_applicable` |
| safe | `9a3f281120307ec7dcce17fae882dcc4e6a6f4d7` | `Singleton<T>::GetInstance` | `9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606` | `ab247369408a389b3744ca0a24f2c87d51115977e0f8860a3388bae856f94800` | 0.129540 s | `completed` / `none` | `not_applicable` |

Snapshot SHA-256 values are `63b3271d7c504a8fb513aa2ea5c51491deb3d7056bcff6f711464a430ff88c75`
for vulnerable and `a4c8bebe389d20fd74d383b0825e8ae9850d61b3de68832c7b6dd7e851c5ca19`
for fixed/safe.

| Role | Native stdout SHA-256 | Native stderr SHA-256 | Normalized SHA-256 |
|---|---|---|---|
| vulnerable | `7606b4e47541834fe170af5805c5a5f1b0df891d470ad12fdf3a0d8ca05d8e00` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `6078619dfe9479c274e0631c3f728ac77bfbf8e4c16c0a512727f129448df345` |
| fixed | `55adea7b2688c0950ed1472cfc9d5e9d018d73f1e3f305ed0970ee54430d2aca` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `0a722ed5d8c03d2c9bf176217b4f2f0e0a99624aa8b65b39b46c7b40333a1a15` |
| safe | `f6dc1364ca6e4a4e0100f53456d754a9ee1ebdd1b390eb9c776c9110da5c8e51` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `362b0c1d9d2b4f6ec655ea838a3b3717752133655ad869d7f3484ba839289d0b` |

The committed native manifest SHA-256 is
`607dbcf7f92857fb3f1495eca157fc0efeca0b52cec96378ae0d4d0cec85cb34`.
The exact raw source bytes are retained only in ignored
`outputs/logs/native_lifetime_replay_2026_10_10/raw/`; their hashes are the
input hashes above. The manifest binds native stdout/stderr and normalized
artifact paths and hashes. Generated files are not committed.

## Coverage, failure and interpretation

- Source retrieval and byte verification are complete for all three cells.
- The detector regex slice reports complete parsing of `base/include/singleton.h`
  in each scoped run. Full build, macro, template instantiation and dependency
  context remain `unknown`.
- Vulnerable execution is `blocked/unknown` because the historical
  `shared_ptr.reset()` / rule-symbol shape is outside the implemented
  `unique_ptr/get/reset` binding. This is not a miss.
- Fixed and safe execution is `completed` only for the selected scope. That is
  not a safe verdict and does not validate concurrency semantics.
- The historical root cause is concurrent `shared_ptr` publication/destruction;
  the safe control is a static-reference accessor. All three cells are explicit
  method-incompatible `not_applicable`, with zero imported detector findings.
- The corpus metadata reports 212/214 lines while raw bytes report 211/213
  splitlines/newlines. This is preserved as `metadata_mismatch_preserved`.
- No PoC, runtime trigger, TSan replay, impact proof, Precision/Recall or
  false-positive/negative claim was produced.

No independent evaluator has frozen or scored a holdout for this method.
