# IPC experiment reproduction

Start with docs/research/ipc_scanner_v0_1_2026-10-10.md. All Python entry points take `--workspace ~/openharmony-audit/ipc-research`; invoke from repository root with `PYTHONPATH=.` and the project's virtualenv. Tools are offline baselines, not scanner runtime dependencies.

1. `import_inventory.py --help` documents original inventory import. Curated corpus already committed; source labels remain versioned.
2. `acquire_sources.py`, `validate_corpus.py`: acquire pinned passive sources and verify98 blobs/hashes, no target execution.
3. `run_own.py`: use existing core fixed-Git runner and plugin registry on twelve paired roots.
4. `run_semgrep.py`: native OSS per-file baseline and raw errors.
5. `replay_baselines.py`: recorded historical Joern/CodeQL/Clang argv; default plan only. Existing CodeQL databases cannot be overwritten; choose fresh paths in copied manifests.
6. `run_synthetic_baselines.py`: fresh independent-TU Joern/CodeQL databases, no overwrite.
7. `run_variants.py`: design controls, ablations and frozen generated variants.
8. `summarize.py`: conservative family/symbol alignment, JSON+UTF8-BOM CSV and raw-manifest hashes. No historical unsafe/safe decision from partial output.
9. `stress_parser.py`: optional repeated source/GC test.

`results/` is an ignored local generated output directory; its README is committed. Generated summaries, target snapshots and raw databases are not committed. Unknown and NA never enter a recall denominator. The corpus is a development/design set; do not publish these ratios as independent real-world recall. Versions and snapshot details are in environment.json and evidence_manifest.json. Third-party source/license inspection manifest is included for provenance, originals remain outside repo.
