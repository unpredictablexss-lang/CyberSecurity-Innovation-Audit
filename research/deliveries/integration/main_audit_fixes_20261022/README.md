# Main audit fixes — 2026-10-22

The user-supplied audit archive targeted main `3069f49a`. Latest main was `13daca3f`, including new efficiency changes; the six original patch targets were still byte-identical. Archive SHA256 entries were verified. The reviewed generator ran only against its exact audited baseline; its output applied cleanly to the latest-main review branch without weakening SHA checks.

Three findings were reproduced before repairs (logs included): ordinary uncapped Worker timeout, recursive cleanup misclassification, and L3 first request prematurely completing the group so a second request failed. Repairs retain deep groups running between successful request settlements and finalize only after the complete Agent returns; one operation owns a group, unknown outcomes remain partial, and retry keys cannot replay billed work. Worker removes the old total timeout only for explicit ordinary uncapped investigations, preserving progressive deadlines. Partial recursive cleanup uses the dedicated CWE-674/availability evidence constructor, version 0.4.3.

Additional review added per-request cancellation checks, shared remaining-time timeout clamping, concurrent schema migration and first-file creation protection. Regression covers the complete two-request orchestration, errors, cancellation, time budgets, atomic ownership, migration and positive/fixed/safe detector controls.

Source fixed-corpus efficiency updates remain intact. Full suite/CI final results are recorded in the PR and external acceptance receipt. No live Provider, deployment, browser acceptance or branch-protection configuration change is claimed. Model findings remain candidate/unknown. No original developer worktrees or services were overwritten.
