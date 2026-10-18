# ETS Frontend post-freeze blind applicability packet

This packet provides 21 unlabelled source excerpts from the separate official `openharmony/arkcompiler_ets_frontend` component. The exact source snapshot is pinned by commit, tree, Git blob OID, and SHA-256 in `blind_manifest.json`. The translation unit parses completely under the light Tree-sitter grammar.

F001 is a `Filter`-suffixed near-match selected after matcher version 0.3.1 was frozen. F002–F021 are 20 function definitions sampled at evenly spaced interior declaration-order indexes after 0.3.2 added adapter-binding checks; the matcher implementation did not change. `prepare_blind_review.py` reproduces the excerpts and reviewer CSV from the pinned source SHA-256. It imports the syntax-only parser, never imports or invokes the C-line detector, and fails if the source digest or parse-complete condition changes.

The prior full-scan worker for this commit stopped before producing a C-line result (`research_c_status=missing`), so no detector output was available or consulted. Labels are absent from the packet. The reviewer should complete `reviewer_labels.csv` with scope, disposition (`candidate`, `partial`, `blocked`, `safe`, or `unknown`), exact evidence lines, and root cause. Until labels arrive, reviewed is 0/21 and unknown/root-cause counts are unmeasured, not zero.

This is a clustered applicability/false-match frame from **one** production translation unit. It can characterize reviewer disagreement and obvious non-applicability in this file after blind labels, but it cannot estimate component-wide precision/recall, test semantic recall, establish behavior in the separate Ark JS runtime, or support a product vulnerability conclusion. Report the 57-function sampling frame and per-sample coverage; do not treat 21 excerpts as 21 independent files.

The mechanism-adjacent `arkcompiler_runtime_core` packet under `holdout-arkcompiler-runtime-core-a053abc4/` remains exploratory because its source was inspected during detector development and is not part of this blind holdout.
