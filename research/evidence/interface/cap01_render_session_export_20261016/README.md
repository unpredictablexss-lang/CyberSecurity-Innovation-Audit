# CAP-01 render-session capability export evidence package

Source-bound competition closure for community-scan candidate
`ohscanner.interface.ipc:eaf73b5d3dd8cbed` in `openharmony/window_window_manager`.

## Result

- Status: `candidate/unknown`
- `validated_vulnerability`: 0
- CVE: `not_assigned`
- Candidate CWE: `CWE-926`; candidate consequence CWE: `CWE-668`
- Product dynamic validation: `unexecuted`
- Component-model dynamic validation: `unexecuted`
- Stable replay: `false`

RC-JSPROXY remained first priority. Its later 2026-10-16 component-model patch revalidation reached
`stable_reproduced_and_patch_revalidated`, but product source/build/permission/deployment/CIA/version evidence
is still missing. Under the required fail-closed rule, this package records why the community fallback was
selected and keeps the fallback candidate unvalidated.

## Contents

- `candidate-closure.md` — complete evidence-gate matrix, entry/call path, boundary, CIA, PoC, patch and unknowns
- `evidence.json` — machine-readable status and identity record
- `source-manifest.json` — exact Git object/source hashes and 18 verified call-path relations
- `poc/harness.cpp` — vulnerable/fixed_control/patched component model
- `poc/run_poc.py` — container-only source verifier, builder and three-repeat runner
- `poc/README.md` — exact isolated Docker command, build flags and output contract
- `patch/minimal.patch` — proposed local authorization guard
- `validation/preflight.json`, `validation/host-preflight.log` — actual source/patch checks and blocked dynamic preflight

## Hard boundary

The harness is not an OpenHarmony product build. It does not establish product reachability, caller identity,
permission grant/deny, SAMGR/SELinux deployment policy, render-session capabilities or CIA impact. The runner
refuses host build/run. No runtime log exists because Docker is unavailable in the current environment.