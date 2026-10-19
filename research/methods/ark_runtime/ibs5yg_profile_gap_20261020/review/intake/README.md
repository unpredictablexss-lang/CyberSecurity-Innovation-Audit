# T5 synthetic intake gate suite

Status: prepared, not yet run against D5. D5's validator/schema has not been delivered to this lane. This suite is intentionally independent of D5 implementation and must be bound to an exact D5 commit SHA before execution.

## Scope and limits

These cases exercise only structural intake behavior: required fields, evidence-byte hash binding and containment, issuer field presence, identity consistency, and rejection of caller-supplied status. `READY` may mean only that the structure is ready for human evidence review. A passing synthetic control does not establish a real issuer, adequate evidence content, custody, product identity, or an IBS5YG product build.

## Cases

`cases.json` defines a canonical input model for the suite. The accepted D5 wire format is not assumed; after D5 delivers a schema and validator, adapt this model into its exact input format without weakening any mutation or expected result. Keep a byte-for-byte canonical copy of each resulting input, hash it, and record the validator commit and command in the eventual result report.

The suite includes:

- Positive control: six required identity values, one common product/build identity, immutable manifest reference, safe in-root evidence reference with matching digest, and issuer present. Expected: structural `READY`/equivalent only.
- Waiting control: minimum values absent. Expected: `WAITING`/`BLOCKED`, never `READY`.
- One case for each missing minimum field.
- Evidence hash mismatch; traversal path; absolute path; symlink/junction escape; missing issuer.
- Conflicting build identifiers; cross-product or mixed-release fields; forged caller status claiming `READY` while gates fail.
- A negative issuer control with a syntactically present but deliberately unverified issuer label. Expected: structural gate may pass only as a declared label, while output must not claim the issuer is authentic or verified.

## Execution protocol

1. Record the immutable D5 commit SHA and validator file hash. Do not test a moving branch name.
2. Inspect the validator's documented invocation and map each canonical case to its exact schema. Do not modify D5 files from this lane.
3. Run each case in an isolated temporary evidence root. Include regular-file, symlink, and (where supported) Windows junction escape controls. If symlink/junction creation is unavailable, report that case as `NOT_RUN`, not PASS.
4. Capture exit code, stdout/stderr, parsed result status, and SHA-256 of every input/evidence byte. Compare with `cases.json` expectations.
5. Send every mismatch to D5 with exact D5 SHA, input hash, command, actual output, and expected output. Re-run the same case set against the new exact SHA after repair.
6. Run `scripts/check_change_scope.py` for lane `c_t5` against base `7b4e6478043b4f26791aa84781093dd965540c9e`; record the output and `git diff --check`.

No case may be described as product identity or profile verification. The initial intake currently has six null minimum inputs, so real target-specific collection remains blocked pending product-owner input.
