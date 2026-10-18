# Runtime Core cross-component review frame

This packet covers official `openharmony/arkcompiler_runtime_core` at pinned commit `a053abc44c608b11d9f9dd10bd681dc222b9d4a9`. The prior 2026-10-18 full-scan worker failed before producing a C-line result for this commit (`research_c_status=missing`). The detector was not run on this frame.

The current deterministic sample has 20 excerpts from 63 name-selected function nodes in the 2,419-line `escompat_TypedArrays.cpp` source file. Required strata include byte-range/native-buffer helpers, `CopyWithin`, `Reverse`, `Fill`, typed-array Set/SetValues paths, and source-array transfer. All 20 selected nodes parse individually, while the translation unit is partial. Build flags, include closure, and product runtime behavior remain unknown.

This source was inspected by the developer while deciding whether it was relevant, before the final 0.3.2 freeze. It is therefore an exploratory cross-component review frame, **not counted as an independent holdout**. The sample was regenerated after freeze using a deterministic ranking, and the reviewer packet contains no detector predictions. An independent reviewer still needs to label all 20 items in `reviewer_labels.csv`; until then, reviewed=0, unknown=20, and root-cause results are unavailable.
