# CAP-01 isolated component replay update, 2026-10-17

A source-bound CAP-01 component model was replayed in the existing `ohscanner-validation:local` Docker image with no network, `--cap-drop ALL`, `no-new-privileges`, read-only root, PID/memory/CPU limits and a writable `/work` bind mount.

## Result

- Source verification: 10/10 pinned blobs and 18/18 quoted relations verified.
- Compiler: Ubuntu clang 14.0.0.
- Sanitizer: UBSan (`-fsanitize=undefined`).
- Variants: vulnerable, fixed_control, patched.
- Scenarios: unauthorized_export, authorized_export, wrong_descriptor, unknown_screen.
- Repeats: 3 per variant/scenario.
- Runtime records: 36/36.
- Mismatches: 0.
- `component_model_dynamic_validation`: true.
- `stable_replay`: true.
- `product_dynamic_validation`: false.
- `candidate_status`: candidate/unknown.
- `validated_vulnerability`: 0.

Expected behavior held in every repeat: vulnerable exports to unauthorized and authorized callers; fixed/patched deny unauthorized callers and export only to authorized callers; wrong descriptor and unknown screen remain denied.

## Boundary

This is a real source-bound, isolated component replay with a proposed local patch, but not a product build or product permission/runtime trace. It does not establish attacker identity, deployed permission policy, render-session capability surface, CIA impact, affected releases or exploitability.

ASan+UBSan was not used for the accepted replay because the combined sanitizer runtime produced intermittent pre-output SIGSEGV under the restricted WSL/Docker configuration. The accepted run is UBSan-only and reports that limitation explicitly.

## Reproduction

The exact container command is recorded in `validation-result-20261017.json` metadata and the original `poc/README.md`; the runner was invoked as:

```text
python3 /opt/cap01/poc/run_poc.py --target /input/target --out /work/validation-result.json --repeats 3
```
