# D44: sensitive-exposure browser acceptance (2026-10-19)

## Scope

This is an isolated browser acceptance of the D sensitive-exposure option through the repository page, scan planner, Worker, finding evidence pane, and report-artifact view. It is a synthetic local Git fixture and validates wiring and evidence preservation only. It is not a product scan, a secret-disclosure finding, an independent accuracy holdout, or a vulnerability confirmation.

## Fixed input and execution

- Worktree branch/head before this documentation-only follow-up: feat/d-commercial-readiness-20261019 at fd443227e00616a0924878c94f0b74ffe990cc16.
- Isolated Workbench: http://127.0.0.1:18766; isolated data and target roots were under /tmp/ohscanner-d43-panel-data-18766 and /tmp/ohscanner-d43-targets.
- Fixture repository: local/d43-panel-fixture, selected ref refs/heads/master, snapshot commit 052f5c0acf5654204b3512d470ee5f4f278d5b69, tree b439c20314be.
- Fixture source contains one heuristic-positive log call and one ordinary integer logging control:

  void Callback(const char *password) { HILOG_ERROR(0, "%s", password); }
  void Safe(int count) { HILOG_ERROR(0, "%d", count); }

- The repository scan page showed separate D options. ohscanner.data.sensitive_exposure was explicitly checked; the disclosed-CVE option remained unchecked. Preview showed 8 attempted rules, 1 not admitted, and 0 files with incomplete parsing. These plan counts do not mean all attempted rules executed or all semantics were covered.
- Browser task: c36f43e2323d4311b7c48562881a4b78, completed with limitations; one source file, one raw candidate observation, zero confirmed vulnerabilities. The candidate is fixture.cpp:1, data.log.sensitive-value, CWE-532, review pending, analysis status partial.
- The evidence pane bound the finding to detector ohscanner.data.sensitive_exposure version 0.18.0, profile light-ast, full source SHA-256 d266af23568ac2e6341d9f4b5ebeead4c014f9e611223f68fb91dc3dcf0d9304, and snapshot SHA-256 ceeded7747ef8d7bb5e7f6e306ab0b4168376c1e35bbb6d0b6e9ffc994e4cbe2.
- The source heuristic is only the identifier password reaching a modeled private/default-private HILOG_ERROR operand. The six visible obligations (local_flow, source_semantics, type_identity, sink_privacy, runtime_log_visibility, and security_impact) all remained unknown; consequence_impact was null. The UI did not promote the candidate.
- The report-artifacts tab exposed manifest, report JSON, report Markdown, review JSON and review Markdown downloads. It displayed original report SHA-256 0b243b530e4a8977ff2cea0dc46d7490060bc53318598978054956ce426eb828 and the matching fixed-source snapshot digest above.

## Result and limits

Browser acceptance passed for the sensitive-exposure option and candidate/report evidence path on this synthetic fixture. The static detector result remains a candidate; all security-impact obligations remain unknown. This does not establish that password denotes a real secret, that a product build emits or retains the log, that an unauthorized reader can access it, or that an affected OpenHarmony product is vulnerable. No product PoC, runtime test, source compilation, or independent human label was performed.

An earlier exploratory fixture revision had invalid C++ quoting and produced no candidate; that run was discarded and is not counted as acceptance evidence. The corrected fixture commit listed above is the only run reported here.
