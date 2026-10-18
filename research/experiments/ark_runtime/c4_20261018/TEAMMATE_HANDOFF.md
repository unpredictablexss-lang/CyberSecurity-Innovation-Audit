# C4 teammate handoff

This note is the short transfer checklist for the C Ark Runtime research lane. The full evidence and limitations remain in C4_HANDOFF.md, C4_SOURCE_BINDINGS.json, C4_REAL_SOURCE_SCAN.md, C4_EXCEPTION_GUARD.md, and C4_UNKNOWN_CASES.md.

## What to take

- OHScanner branch: work/c4-ark-runtime-20261018. The initial C4 code checkpoint was e48151a8d527872deb79415d3512acfdfbbdce1e; this guide is a later documentation commit on the same branch. It contains the C4 detector, default-off catalog integration, explicit panel selection, exact-source applicability checks in Runner, regression tests, and C1–C4 experiment records.
- The Ark source repository is separate. Do not copy OHScanner code into it. Point OHSCANNER_ARK_REPO at the teammate's local openharmony/arkcompiler_ets_runtime Git checkout/object database; the tests read pinned objects with git show and do not change the source checkout.
- independent_review_packet.zip is a separate packet of synthetic control cases with blank labels. It is for independent semantic review, not upstream code or a vulnerability PoC.

## Safe checkout and replay

Fetch the branch and add a separate OHScanner worktree so any existing dirty checkout stays untouched:

```bash
git fetch origin work/c4-ark-runtime-20261018
git worktree add ../ohscanner-c4-handoff origin/work/c4-ark-runtime-20261018
cd ../ohscanner-c4-handoff
```

Set OHSCANNER_ARK_REPO to the teammate's existing Ark Runtime clone. From the OHScanner worktree, install Python dependencies with python -m pip install -r requirements.txt. Before running the tests, verify that the local object database contains all four target revisions:

```bash
for rev in \
  830e85b40240677039719fcbf14f721ad3b19050 \
  a0e30483ab3e4aead67ecfb5c708489915e447f9 \
  c758818dbfd0b146a908d43d21f6ca1706c33783 \
  81ca57487d04ea30cd11c271e86494a4e130f43e; do
  git -C "$OHSCANNER_ARK_REPO" cat-file -e "$rev^{commit}" || exit 1
done
```

If any object is missing, stop before interpreting a skipped historical test as a pass. Prepare the missing commits in a separate source mirror only if the teammate authorizes fetching; the test suite itself deliberately performs no implicit network fetch. Then run:

```bash
python -m unittest discover -s tests/detectors/ark_runtime -t . -v
python -m unittest discover -s tests -q
```

On Linux, set the variable with export OHSCANNER_ARK_REPO=/path/to/arkcompiler_ets_runtime. On PowerShell, set it with $env:OHSCANNER_ARK_REPO = 'C:\path\to\arkcompiler_ets_runtime' before the commands. The full-suite result recorded for this checkpoint is 922 tests, 914 passed, 8 skipped, 0 failed; the focused detector result is 215 tests, 212 passed, 3 skipped, 0 failed. Missing local commits explain three historical replay skips in the recorded environment.

## Findings and decision boundary

At the fixed source revisions, the type-origin rule preserved one parent Filter candidate and none on the fix; the separate allocation-exception rule preserved two parent candidates (Filter and Map) and none on its fix. Every replay stayed partial/blocked. The panel task showed the candidate and validated_vulnerability=0. These are source-bound research candidates and rule regressions; they do not confirm a product vulnerability, prove the whole component safe, or establish commercial precision/recall.

The detector is version 0.6.1, explicitly selected and default-off, and only applies to its exact repository/path/source bindings. The current upstream tip did not match those bindings because the parser lost the namespace on Filter/Map; ToReversed, product build identity, reachability, runtime behavior, exploitability, and impact remain unknown. Do not broaden bindings or turn off partial/unknown gates just to obtain more results. PR #16 remains Draft; this branch push did not create or update a PR.

## Review checklist for the receiving teammate

1. Verify branch SHA and diff before any cherry-pick or merge.
2. Run the pinned-history tests against the local Ark object database; check that no revisions were silently skipped.
3. Independently review the model, partial-result contract, and synthetic holdout labels. The labels are not ground truth until independently reviewed.
4. If pursuing a product-level claim, first bind the deployed Ark build and flags, then arrange an isolated runtime reproduction and collect reachability/impact evidence. Keep all results candidate/unknown until that evidence exists.
