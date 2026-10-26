# Method card: D sensitive log material

Original implementation by this work session; no third-party detector/rules copied.
Parsing infrastructure: existing project Tree-sitter C/C++ dependencies and real core contracts.
Family: CWE-532 candidate only. One rule data.log.sensitive-value, version0.1.0.

Input: pinned SourceUnits + actual ast eligibility + exact repository/commit model.
Method: semantic material-field/callback/output models -> bounded local value dependencies ->
per-operand public log format mapping -> source-bound finding and unknown obligations.
Output: actual DetectorRun/Finding/file_outcomes, v2 normalization by existing runner.
Innovation within narrow scope: separates material from key metadata/status, tracks overwrites and
format operand positions, does not assume masking/hash wrappers safe, preserves partial evidence.
No claim of algorithmic novelty over research literature, full taint, accuracy or real vulnerability.

Provenance: official-organization communication_dsoftbus and hiviewdfx_hilog pinned commits in
source_manifest.json/source_locations.json. References by symbol/location/hash; original vendor
implementations kept outside tracked source. Reviewed LICENSE files are Apache-2.0; no upstream
copyright headers removed or copied into original implementation. See D_REVIEW for scope/results.
