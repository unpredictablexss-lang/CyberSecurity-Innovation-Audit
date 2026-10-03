# Historical vulnerability benchmark

This directory contains published historical security-fix pairs used as ground
truth for evaluating the audit pipeline.

## What this benchmark measures

For each sample we pin the repository, vulnerable commit, fixed commit, affected
files and symbols, published weakness/root cause, and public source references.

The runner verifies the commits locally, checks whether the fix diff touches the
expected files, materializes only those files from both revisions, and runs the
current text candidate generator plus the lightweight tree-sitter AST index.

The output records whether the current candidate generator overlaps the known
affected region.

## What it does not measure yet

A positive-only historical set cannot honestly provide full Precision or false
positive rate. One known sample also does not provide a meaningful global Recall
estimate.

Do not interpret a candidate overlap as a validated vulnerability, a miss as
proof that no other project layer could detect the case, a historical replay as
a new vulnerability discovery, or a fixed revision with zero candidates as
proof of safety.

The first seed is the published c_utils singleton.h UAF fix. It is useful
precisely because the current dangerous-API scanner is expected to miss this
concurrency/lifetime bug, exposing a real capability gap that later
lifetime/concurrency analysis should address.

## Target size

Grow this set to 3-5 first-party OpenHarmony historical fixes spanning multiple
root-cause families before reporting benchmark rates. Keep duplicate backports
or near-identical fixes in one root-cause group.
