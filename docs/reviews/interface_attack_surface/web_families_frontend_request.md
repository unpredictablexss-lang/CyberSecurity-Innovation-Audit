# Web families prototype and frontend extension request — 2026-10-09

Branch: feat/oh-interface-detectors. Development and tests executed in Ubuntu.
No global registration/CLI/schema changes, third-party code, commit or push.

## Delivered scope

`src/ohscanner/detectors/interface/web_patterns.py` provides four actual Detector-contract entry points:

- BridgeInjectionDetector: nonliteral first argument to `.runJavaScript(...)`, including concatenations, variables and templates. Candidate only; no proven input control, exposed native target, injection or authorization bypass.
- WebUrlDetector: URL-looking literal arguments to `.startsWith`, `.includes`, `.indexOf`. Raw string comparison review only; unrelated receivers, legitimate comparisons and later guards can be false positives. Redirects, races and actual navigation linkage are not analyzed.
- SensitiveDisclosureDetector: literal `.fileAccess(true)` and `.mixedMode(MixedMode.All)` calls. Configuration review only; these options do not prove sensitive files or Cookie/Token disclosure. Header-to-sink and file-permission analysis are not implemented.
- WebEngineDetector: explicitly blocked, no findings. NOT an implemented engine memory-safety detector or version/CVE checker. Needs actual native engine context and coordination with teammate A. Application settings cannot establish an engine vulnerability.

Deferred imports use real owner contracts, not fake contracts. Production execution has no external scanner/network/shell. Integration was tested with core 8c5c9d9b77857d9ccf41d101be6068f287453e81; owner registration is still pending.

## Method and coverage

Original bounded lexical method groups strings/comments and balances parentheses to locate member-call arguments and source lines. No AST/CFG/dataflow claims. Comments and quoted code are excluded in tested examples. Regular-expression literals, nested template expressions, escapes, computed properties, aliases, Unicode identifiers, malformed source and dynamic dispatch are not fully parsed. Calls may be missed or spurious. API names have no receiver type proof.

required_facts=() means this layer reads supplied source text only. Failed parse units are withheld; not_run/partial units may emit pattern candidates while preserving original parse status. Completed refers ONLY to lexical review. Every finding carries unknown API identity, attacker-control, guard/impact and frontend obligations. No finding is a safety result. Engine status remains blocked.

Reference (API behavior, not a pinned vulnerability example):
https://github.com/openharmony/docs/blob/master/en/application-dev/faqs/faqs-arkui-web.md
The official FAQ describes javaScriptProxy/runJavaScript and mixedMode. This moving documentation reference is not an exact-version API catalog or a real positive/fixed pair. No vendor source/rules copied. Algorithm and fixtures are original.

## Frontend request for owner review

1. JS/TS/ArkTS AST with accurate locations, parse errors, member calls, template expressions and receiver/binding identity. Input: c.runJavaScript("alert(" + input + ")"); expected: call, first argument expression, symbol identities, parse coverage. A string/comment containing that text must not become a call.
2. Explicit bridge export-to-target edges for javaScriptProxy/registerJavaScriptProxy including object, methodList, origin scope and ArkTS/native target. Unknown mapping must remain unknown. No private schema becomes mandatory before owner approval.
3. Function-local provenance and guard facts. Input: navigation callback checks URL.protocol + hostname, then loadUrl; expected: source, normalized URL fields, exact host/scheme checks, sensitive call and branch relationship. Prefix comparison alone cannot prove navigation bypass; callback inversion and redirects need explicit semantics.
4. Sensitive-data source/sink facts: Cookie/Authorization response fields, logs, bridge returns, network outputs, canonical local file paths and effective permissions. Include bounded inter-function relations and unresolved calls.
5. Engine revision/build/backport evidence and reviewed native AST/CFG/type/lifetime models. Coordinate native bounds/concurrency ownership with A. Start from one verified vulnerable/fixed/safe pair, not broad generic memory warnings or version-only vulnerability claims.

The above requests are prepared locally, not sent to owner and not approved. Shared frontend/IR and catalog remain owner's responsibility.

## Fixtures and validation

10 lexical regression tests include synthetic candidate/fixed-like/safe cases, comment/string controls, multiline locations and incomplete calls. They are not real vulnerabilities or independent holdout. Four Web core tests verify actual bridge normalization/unknown obligations, parse-failed withholding, engine blocked and deterministic diagnostics; existing four IPC core tests remain green.

Ubuntu main-based branch full suite: 261 cases, 253 passed, 8 core-dependent skips. Actual core worktree: all 8 interface adapter tests passed. Log: outputs/logs/ubuntu-web-full-tests.log.

Remaining acceptance work: pinned official API catalog, real positive/fixed/safe vulnerability samples, independent holdout, reviewed frontend extension, concrete reachability and policy evidence, owner review/registration. validated_vulnerability=0. Four-family semantic detection is NOT complete.
