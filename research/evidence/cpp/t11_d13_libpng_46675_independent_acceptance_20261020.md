# T11 independent acceptance: libpng CVE-2026-46675

Date: 2026-10-20  
Checkout: `codex/a-t11-d13-independent-20261020`  
Baseline: `771d0b9b6fd44cb9a813cef6f3161fcc64ab2d48`  
Disposition: **PARTIAL/BLOCK**

## Independent source identity check

Fetched the exact upstream vulnerable and fixed commit objects directly from `pnggroup/libpng`, then checked each commit tree and `pngrutil.c` entry using `git show -s --format='%H%n%T'` and `git ls-tree`.

| Variant | Commit | Tree | `pngrutil.c` blob | SHA-256 | Bytes |
|---|---|---|---|---|---:|
| Vulnerable | `c3e304954a9cfd154bc0dfbfea2b01cd61d6546d` | `e01f5780f93eaa6d74cca003bb39b427c8f1e910` | `a4eda54c8cb3d36cf1651dba159067b65030e3aa` | `b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e` | 153112 |
| Fixed | `aa77ef38c17ab2fc1b41bec09fb973c6a386641d` | `4c64b5f18cef7d129adee3b403fc4be93f82e30d` | `482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a` | `a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e` | 152477 |

This confirms the earlier D13 file/blob hashes and corrects its stale statement that the tree IDs were unavailable. GitHub's advisory identifies the issue as CVE-2026-46675, affects libpng through 1.6.58, and lists 1.6.59 as patched. The fix commit clears zstream input/output pointers and counters on claim/release paths. Sources: [official advisory](https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j), [fixed commit](https://github.com/pnggroup/libpng/commit/aa77ef38c17ab2fc1b41bec09fb973c6a386641d).

## Independent replay

Replayed `CppResourceLifetimeDetector` 0.4.0 on the exact SHA-verified full-file bytes. Vulnerable and fixed `pngrutil.c` both parsed `partial` with 72 issues; each run returned `blocked` and zero findings. This was direct detector invocation, not a full pinned-source CLI run.

Re-ran the paired function-fragment replay using the unchanged D12 script. On both variants, six of seven fragments parsed completely; `png_handle_iCCP` remained partial. All fragments yielded zero findings, and both parent translation units remained partial. Fragment syntax success does not establish cross-function ownership/call-order coverage.

The vulnerable side has no candidate, so a zero-finding fixed result cannot count as a fixed differential or safety proof. This case remains PARTIAL/BLOCK.

## Follow-up required

- Model and validate release-to-IDAT zstream state across functions.
- Resolve the `png_handle_iCCP` parse issue and improve full translation-unit coverage without weakening parse-status reporting.
- Add vulnerable, exact fixed, row-reading, malformed-chunk, safe, and unrelated controls before claiming a differential.
- Keep trigger feasibility and OpenHarmony product reachability as separate evidence requirements.

Machine-readable results: [acceptance JSON](t11_d13_libpng_46675_independent_acceptance_20261020.json), [fragment replay JSON](t11_libpng_46675_fragment_replay_20261020.json).
