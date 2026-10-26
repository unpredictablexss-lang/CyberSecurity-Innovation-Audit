# curl CVE-2026-92391 recursive MIME cleanup candidate

Verification date: 2026-10-19. The official [curl advisory](https://curl.se/docs/CVE-2026-92391.html) identifies uncontrolled recursion in `curl_mime_free`, affecting 7.56.0 through 8.22.0 and fixed in 8.23.0. It says a deeply nested multipart structure constructed through the public API can exhaust stack during ordinary cleanup. This is an API-driven resource exhaustion case, not a remote-server parsing flaw by itself. OpenHarmony application reachability/control remains unknown.

## Root-cause card

1. **Control and conditions.** A caller that can construct a deeply nested MIME tree can control its depth. Whether an OpenHarmony application passes attacker-influenced content into the MIME construction API and invokes cleanup on it is unknown. The advisory says thousands of nested parts may be required, depending on stack/system.
2. **Object flow.** `curl_mime_subparts` calls `Curl_mime_set_subparts`, which stores child `subparts` in the parent part's `arg` and stores `mime_subparts_free` as its `freefunc` when taking ownership. `cleanup_part_content` invokes `part->freefunc(part->arg)`. The callback calls `curl_mime_free` on the child; cleanup reaches the nested part callback again. A nested object graph therefore creates a callback-mediated recursive cleanup cycle.
3. **Missing invariant.** The vulnerable version has no bounded recursion depth or iterative traversal in this cleanup cycle. A stack frame is consumed for each nested child.
4. **Patch invariant.** Upstream commit `d7546809d5bd548b69ec49fca26565c8f6f0d344` rewrites `curl_mime_free` as an iterative parent-chain walk. It detaches nested subparts, repurposes `parent` to hold pending traversal, and frees each level without recursively calling the cleanup callback. The patch adds upstream libtest `test3595` (`lib3595.c`) to exercise freeing 50 nested MIME levels. That test was inspected but not compiled/run here.
5. **Static proof and obligations.** Rule 0.1.9 requires a callback stored in a member alongside nested pointer data, a callback-to-cleanup call path, a cleanup dispatch through the same member that closes the cycle, a release-shaped operation on that path, and no explicit depth guard in the modeled cycle. It does not prove runtime callback value, exact object identity, feasible path, attacker-controlled nesting, stack limit, or impact; these remain explicit obligations.
6. **Safe lookalikes.** A callback cycle whose member is cleared before entering the cleanup helper breaks the modeled path; a cleanup chain explicitly bounded by a depth check is suppressed; direct recursion unrelated to nested-resource cleanup is not reported; iterative teardown has no callback recursion cycle. Inline tests cover these controls.

## Source identities

Source was explicitly fetched from the GitLab omnibus mirror of `curl/curl`; scanner replays read local Git objects only and did not fetch.

| Source | Commit | Tree | `lib/mime.c` blob | File SHA-256 |
|---|---|---|---|---|
| curl 8.8.0 upstream tag | `fd567d4f06857f4fc8e2f64ea727b1318f76ad33` | `2d2098e48360a42ef4621efb1ce1d13ed0e1b708` | `a2356c473869615bc99713ebe64b21a269ab529d` | `8792533ae41c4a51699997e9448c46194f7ad22ec6c181faa2b4702afe56f066` |
| curl 8.22.0 affected tag | `01346829096c61b372692f6dc43ffa778c6caccd` | `6ae23d9333713707a02588b44ed238a50e8b3bde` | `600437576581be08f9026881c39178857a1c5939` | `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d` |
| Fix parent | `10c5f8e72238e94e62d6d35a6ebd34ddb5bca1df` | `d49558109ddc4b587fafe2eff1c19b11917c65b6` | `635eb310ad2081f8d2e213b908c939ff6ec9acb7` | `b07d2332f13c2e529fbbe4c88251bb28c02b9154bf70c0ac31a675cc53b0088e` |
| Fix commit | `d7546809d5bd548b69ec49fca26565c8f6f0d344` | `52a8416729366487cdd3b6012071f5f8370e769f` | `3522679a16e2fa560c581413bf946d38e332bea4` | `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81` |
| curl 8.23.0 fixed tag | `3163ec065643ba20709f190111f42c3e1fe95273` | `4e5e74de5a67ab3268dffc8999ba72b5ce41c0b8` | `f491f22f95ac495205925f6025d49fc5f7943d45` | `651178f1a254072797a8e9aa8f4146a6f949f63a1eb828db7c379f271ff8734f` |

The advisory names the introduction commit by short hash `ce0881edee3c78609eae49`; its official patch gives full identity `ce0881edee3c78609eae49665fb70264d8786d29`, tree `e4f5cda7865f3e73664dca5c4eb6a7a648c1e2d2`, `lib/mime.c` blob `759ade08599c3d13acbef002d67f70d31207fa53`, SHA-256 `780c0d838e8b46fc364794548b7329d6d505b4da9f4d5e04b93d64394d40ce78`.

OpenHarmony manifest pin: `third_party_curl` commit `1386bb128bb060b284309397b97adcaaec21c003`, tree `b96addd5821a610eb0ceacc7e7a83deda64690c2`; local `lib/mime.c` blob `1f94afee2c93300a4bf70e743dbd552075cb8b1c`, SHA-256 `e3a41025c00fa47b1b23bff6d28ac66119b7d5bd13035e3436c817a6ca53327b`. The checked-out submodule `.git/config` is unreadable on this Windows mount, so commit/tree binding comes from the fixed OpenHarmony manifest and local file hash, not a successful Git-object traversal. The file was copied byte-for-byte into a synthetic local Git snapshot; that synthetic commit is not called the upstream source commit.

`third_party/curl/BUILD.gn` includes `lib/mime.c` in `curl_source` and uses that list for curl library targets. The specific product target/profile and application reachability are not established.

## Production scans and baseline

Production entry: `python -m src.cli ohscan-run`; one-file `lib/mime.c` scope; detector `ohscanner.cpp.resource_lifetime`; no CVE metadata supplied.

| Source | Detector | Diagnostics | Parse | Elapsed |
|---|---:|---:|---|---:|
| OpenHarmony local 8.8.0 snapshot (`2b7419e1dcb97d99a8e65105a66dcb8331fcb6d4`) before rule, v0.1.8 | 0 | complete | 0.0746 s |
| curl 8.22.0 before rule, v0.1.8 | 0 | complete | 0.0751 s |
| exact fix parent before rule, v0.1.8 | 0 | complete | 0.0762 s |
| OpenHarmony local 8.8.0, v0.1.9 | 1 at `lib/mime.c:1589` | complete | 0.1251 s |
| curl 8.22.0 affected tag, v0.1.9 | 1 at `lib/mime.c:1509` | complete | 0.1223 s |
| exact fix parent, v0.1.9 | 1 at `lib/mime.c:1509` | complete | 0.0861 s |
| exact fix commit, v0.1.9 | 0 same-rule candidates | complete | 0.1360 s |
| curl 8.23.0 tag, v0.1.9 | 0 same-rule candidates | complete | 0.1415 s |

Elapsed time is detector-run time from the M2 report; peak memory was not reported. The local OpenHarmony hit is candidate evidence, not product vulnerability confirmation. The v0.1.8 baseline is a detector capability miss (complete parse, no recursive-cleanup rule), not a parser/scope failure.

A renamed/wrapper mechanism variant was held out until after implementation and scanned through production CLI without CVE metadata: one candidate, complete parse, synthetic commit `64e5f0a007b800bf693591636a30b66fdd3b499d`. Its final-code replay took 0.0027 s. It is a synthetic mechanism check, not an independent real-world sample. Final-code source-bound reports are `verified-v8.22-final.*`, `verified-fix-parent-final.*`, `verified-fixed-final.*`, `verified-oh-final.*` and `verified-holdout-final.*`.

## Tests and limits

- Focused tests: 3 selected tests pass, including recursive positive, iterative fixed, bounded recursion, unrelated recursion, incomplete parse, and prior cross-member UAF controls.
- Full resource-lifetime module: 9/10 pass. The remaining manifest test fails on a dirty fixture size mismatch: `positive_double_free.cpp` is 116 bytes; manifest expects 110. Neither fixture nor manifest was changed.
- Component runtime reproduction: independently re-run this turn against the saved, hash-recorded static binaries. On a 256 KiB WSL thread/process stack, vulnerable depth 50 and fixed depth 50 exit 0; vulnerable depth 10,000 exits 139 during cleanup; fixed depth 10,000 exits 0. Exact replay logs are `verify-vulnerable-depth50-stack256.log`, `verify-vulnerable-depth10000-stack256.log`, `verify-fixed-depth50-stack256.log`, and `verify-fixed-depth10000-stack256.log`. Upstream `test3595` source was inspected but was not run.
- No independent labeled corpus; no precision/recall claim.
- Callback dispatch/cross-function paths are approximated lexically. Object identity, path feasibility, API caller, attacker control, stack limit and product CIA impact remain unknown.

Replay examples (bare repo: `D:\openHarmonyScanner\tmp\curl-upstream-pins-20261019.git`):

```powershell
python -m src.cli ohscan-run --repo-dir <bare-repo> --repository curl/curl --commit 10c5f8e72238e94e62d6d35a6ebd34ddb5bca1df --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out parent.json --md-out parent.md
python -m src.cli ohscan-run --repo-dir <bare-repo> --repository curl/curl --commit d7546809d5bd548b69ec49fca26565c8f6f0d344 --include lib/mime.c --detector ohscanner.cpp.resource_lifetime --json-out fixed.json --md-out fixed.md
```

Full reports and the synthetic holdout sit beside this note. The source-transfer bare repo is temporary under workspace `tmp`, not a delivery artifact.

## Root-cause card and component runtime closure (2026-10-19)

- **Attacker input / unknowns:** the public curl advisory describes caller-constructed nested MIME parts; the harness creates nesting only through public `curl_mime_init`, `curl_mime_addpart`, and `curl_mime_subparts`. No network request is made. Whether a product application lets a remote attacker choose MIME nesting depth, which process invokes this API, and its stack/resource limits remain unknown.
- **Flow:** each MIME part owns a child MIME object through `subparts`; destruction dispatches `part->freefunc(part->arg)`; the child cleanup callback recursively enters `curl_mime_free`, consuming C stack proportional to nesting depth.
- **Missing invariant in 8.22.0:** nested cleanup has no depth cap or iterative traversal. The fix commit `d7546809d5bd548b69ec49fca26565c8f6f0d344` walks parent/child ownership iteratively, avoiding a C frame per nesting level.
- **Static proof obligations / limits:** the current candidate rule looks for callback registration, stored nested object, cleanup dispatch, and a recursive cleanup cycle. It does not prove path feasibility, a concrete caller, attacker control, or process impact; those stay unknown. Ordinary bounded recursion and unrelated recursive functions are controls, not findings.
- **Runtime setup:** built exact curl 8.22.0 commit `01346829096c61b372692f6dc43ffa778c6caccd` and exact fix commit above as static libraries using workspace CMake 4.4.4 + WSL GCC 16.2.0, with tests/executable/shared libraries and optional TLS/compression backends disabled. Harness SHA-256 is recorded exactly in runtime-hashes.txt.
- **Observed results:** vulnerable depth 50 reached `cleanup completed`; vulnerable depth 10000 printed `freeing root` and bash reported SIGSEGV with core dumps disabled and 256 KiB stack. Fixed depth 50 and depth 10000 at the same 256 KiB stack both reached `cleanup completed`. Executable and harness SHA-256 values are in `runtime-hashes.txt`. This is an offline component reproduction; no product exploit or service availability claim follows.
- Raw build logs, source identities, runner and output logs are adjacent: `cmake-vulnerable.log`, `cmake-fixed.log`, `runtime_recursive_mime.c`, `runtime-vulnerable*`, `runtime-fixed*`, `upstream-test3595.c`. The upstream test source was inspected but not executed; this harness is our local reproduction.

Signal observation and exact harness/binary hashes are saved in runtime-vulnerable-signal.log and runtime-hashes.txt.


## Independent replay in current scanner checkout (2026-10-19)

Using the local pinned bare source repository and current scanner checkout HEAD `9b99f106883ef58304d9e6702fea562bb7f8f331`, the production M2 CLI was rerun with no CVE metadata, detector `ohscanner.cpp.resource_lifetime` 0.1.9, and one-file `lib/mime.c` scope:

- Vulnerable curl 8.22.0 commit `01346829096c61b372692f6dc43ffa778c6caccd`, tree `6ae23d9333713707a02588b44ed238a50e8b3bde`, source SHA-256 `1f3388f52881524fda0bc11c453aca75adda7d7e77d65393ec558d396dc3483d`: 1 candidate at `lib/mime.c:1509`, complete parse.
- Exact upstream fix commit `d7546809d5bd548b69ec49fca26565c8f6f0d344`, tree `52a8416729366487cdd3b6012071f5f8370e769f`, source SHA-256 `ea7f9adccf81b578d97e8b6e115535e043b7f8c589177a2597963a4f12462b81`: 0 same-rule candidates, complete parse.
- Reports: `replay-vulnerable-8.22.0.json/.md` and `replay-fixed-commit.json/.md`. Both scans completed using the same production CLI, detector version, source scope, and local pinned source store; the fixed report is a no-finding result for this root-cause rule, not a blanket safety verdict.
- Focused module re-run: `python -m unittest tests.detectors.test_cpp_resource_lifetime_detector -v`: 9 passed, 1 failed. The sole failure is the pre-existing hash-bound manifest size mismatch (`positive_double_free.cpp` actual 116 bytes, expected 110). No fixture/manifest changes were made.

## Current-checkout replay (2026-10-19)

Replayed exact local pinned sources through the production M2 CLI from scanner HEAD `9b99f106883ef58304d9e6702fea562bb7f8f331`, detector `ohscanner.cpp.resource_lifetime` v0.1.9, with no CVE metadata:

- Vulnerable curl 8.22.0 commit `01346829096c61b372692f6dc43ffa778c6caccd`: complete parse, 1 recursive-cleanup candidate at `lib/mime.c:1509`, 0.0894 s.
- Exact fix `d7546809d5bd548b69ec49fca26565c8f6f0d344`: complete parse, 0 same-rule candidates, 0.0823 s.
- Post-freeze structural holdout commit `64e5f0a007b800bf693591636a30b66fdd3b499d`: complete parse, 1 candidate at `variant.c:12`, 0.0020 s. Synthetic holdout only.

Fresh reports are `revalidation-v019-{vulnerable,fixed,holdout}.{json,md}`. Focused recursive callback-cycle and release-wrapper controls passed 2/2. This revalidation confirms detector behavior on exact component files; callback-cycle feasibility at a concrete product call site, attacker control of nesting, configured stack/resource limit and product impact remain unknown. Prior component runtime evidence is separately recorded; this CLI replay did not run binaries.


## Current-turn focused recursive-family regression (2026-10-19)

Ran the existing detector test methods for recursive cleanup callback cycle/controls, fixed/unrelated/unknown controls, release-wrapper controls, and deterministic output/budget. Result: 4/4 passed. Command:

```powershell
python -m unittest tests.detectors.test_cpp_resource_lifetime_detector.ResourceLifetimeDetectorTests.test_recursive_cleanup_callback_cycle_and_controls tests.detectors.test_cpp_resource_lifetime_detector.ResourceLifetimeDetectorTests.test_fixed_unrelated_and_unknown_controls tests.detectors.test_cpp_resource_lifetime_detector.ResourceLifetimeDetectorTests.test_release_wrapper_controls tests.detectors.test_cpp_resource_lifetime_detector.ResourceLifetimeDetectorTests.test_deterministic_output_and_budget -v
```

This targeted result does not clear the known full-module fixture manifest mismatch (9/10 in prior module run), and does not upgrade product reachability or impact evidence. The real source CLI comparison remains vulnerable 1 / exact fixed 0 on complete parses, with a post-freeze synthetic wrapper variant 1.
