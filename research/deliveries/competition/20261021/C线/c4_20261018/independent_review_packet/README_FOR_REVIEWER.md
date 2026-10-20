# Independent semantic review packet

This packet contains 16 small C++ source samples (`cases/H01.cpp` through `H16.cpp`) and a blank label template. It intentionally excludes detector predictions, rule outcomes, and developer rationales. Do not request or inspect those until all labels are signed and frozen.

For each sample, classify the source-level TypedArray type-origin mechanism using only the evidence visible in the sample:

- `risk_mechanism`: the code can use a type token that is not established for the object receiving the typed store.
- `reliable_same_type`: the code establishes that the type token and store destination refer to the same actual typed-array type through the relevant path.
- `unrelated`: the sample does not exercise this mechanism.
- `unknown`: the snippet omits declarations, effects, control flow, or runtime facts needed to decide.

For every label, record a short rationale and exact source evidence. If the classification depends on runtime or build assumptions, state them and prefer `unknown`. Record the reviewer identity/date and return the completed JSON with no edits to sample files.

These are developer-produced synthetic/control snippets. This review can check semantic labels and implementation behavior; it cannot establish real-world precision, recall, product impact, or commercial readiness by itself. A separate, independently sourced real-code corpus is still required before making those claims.

Verify the sample SHA-256 values in `labels.template.json` before labeling. The source hashes are the sample identity; do not relabel a changed sample under the same ID.
