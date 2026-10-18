# Ark Runtime exception-propagation research replay

## Scope

This is a research-only exact-source replay for `panda::ecmascript::kungfu::SlowPathLowering::LowerCallStubWithIC`. Detector `ohscanner.ark.runtime.exception_protection` v0.1.0 evaluates rule `ark.runtime.callstub.pending-exception-propagation`. It is deliberately not registered in the product catalog.

## Bound inputs and result

`replay_exception_rule.py` verifies each extracted input against its pinned repository commit/tree/blob and SHA-256 before invoking the analyzer. See `raw-results.json` for full input bindings, profile, source outcomes, obligations, limitations, and results.

- Parent: one `candidate` for the `CallStub` result replaced through `ReplaceHirWithValue`.
- Fix: direct rule result `matched`; no Detector findings. The aggregate DetectorRun remains `blocked` because the whole translation unit is only partially parsed.
- Safe control: `matched` (safe/unrelated-to-the-anti-pattern pattern within the exact owner).
- Unrelated `LowerCallRuntime` control: `not_applicable` to this exact target rule.

The candidate transition is reproduced, but it is not a proof of CFG dominance, state/depend correctness, runtime behavior, exploitability, or overall component safety. All such evidence obligations remain open; the fixed source's zero findings is not a whole-component safety claim.

## Dependency comparison

The type-origin replay recorded `tree-sitter 0.26.0`, `tree-sitter-c 0.24.2`, and `tree-sitter-cpp 0.23.4`, matching the frozen C3 parser packages. This replay records the same parser package versions in `raw-results.json`. Python is 3.13.9 here versus 3.12.0 in the archived C3 run, so Python-runtime drift remains a comparability limitation.

## Reproduce

From repository root, run the commands in `commands.txt`. The focused tests exercise the parent/fix/control behavior and fail closed on source binding mismatch. `hash-manifest.json` covers this experiment, detector implementation, relevant tests, and pinned source extracts; `hash-manifest.sha256` is the detached digest of that manifest.
