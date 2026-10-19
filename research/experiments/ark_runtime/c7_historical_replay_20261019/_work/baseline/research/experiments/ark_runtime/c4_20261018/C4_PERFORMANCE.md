# C4 bounded performance observation

The timed region called parse_source and then analyze_exception_guard directly for each exact pinned parent/fix source. Each revision had one warm-up and two measured runs on Python 3.10.12 / Ubuntu 22.04 WSL. Raw per-run observations are in C4_PERFORMANCE.json.

The 152 KB translation unit took 0.162–0.185 s in recorded runs (parent run 1: 0.183 s). The parent produced the same two candidates on both runs; the fix produced the same two matched observations. Both stayed partial because the translation unit has parser/dependency gaps. Extra analyzer invocations used about 13.1–13.2 MB peak traced Python allocation. Reported process RSS is cumulative process high-water, not isolated per-file RSS.

This excludes checkout, platform queueing, Worker/API serialization, other detectors, and repository-scale aggregation. It is not a throughput or capacity claim. No compatible Ark runtime executable was present (ark_js_vm, ark_js_runtime, es2abc, and hb were absent), so no dynamic test or PoC ran.