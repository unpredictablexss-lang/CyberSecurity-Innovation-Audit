# Validation snapshot, 2026-10-17

- Remote branch: `codex/full-runtime-performance-audit-20261014`.
- Latest local commit before this snapshot: `ca80ec86c0d4bc0a3e8e759d134fde23e2dee56b`.
- Full Python regression: 719 executed, 711 passed, 8 skipped, 113.122s.
- A/B/public targeted suites: 51 workbench/M2 tests, 3 fact-v2 tests, 1 cross A/B test, 4 ArkTS/JS tests passed.
- `compileall`: passed.
- Web build: TypeScript `tsc --noEmit` and `node build.mjs` passed with the existing `web/node_modules`.
- `pnpm run build` was not used as the authoritative check because the environment lacks `npm`; pnpm attempted dependency installation and stopped on its ignored `esbuild` build-script policy. This is recorded as an environment/tooling limitation, not a web build failure.
- Docs context budget: `default=12032/13500`, `docs=21237/32500`.
- JSON evidence parsing: passed.
- `git diff --check`: passed.

The taskbook status remains incomplete because product-level closure, all-community scale and large independent labelled holdout remain open.
