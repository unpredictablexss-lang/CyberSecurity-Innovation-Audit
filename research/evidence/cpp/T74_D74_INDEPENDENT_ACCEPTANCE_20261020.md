# T74 independent acceptance — D74 cross-layer source trace

## Verdict

D74 is accepted as a bounded, source-anchored trace. No actionable mismatch was found in the examined route, permission evidence, source identities, report boundaries, or second-layer prompt. This acceptance confirms repository-source observations only; product deployment, external platform enforcement, authorization semantics beyond the checked code, and CVE/product conclusions remain unknown.

## Frozen identity and scope

- Reviewed frozen D74 commit: `a29275f7a795da17171fd3df2c712ef3a8576cb7`.
- Independent acceptance checkout was clean at that commit before this report.
- Commit changes only the D74 Markdown report, structured JSON evidence, and reproduction script; it changes no detector, fixture, expected output, or upstream source.
- D52 historical repo identity: `openharmony/miscservices_pasteboard`, commit `dd22c7cb5e5f207a6c38c50f45b7369ee8575840`, tree `e374a0d61c9ec664ddd29fc17002797828c480ee`.
- Current repo identity: `openharmony/distributeddatamgr_pasteboard`, commit `e73747b227104e6743e957ce31040edf58507221`, tree `4128cdf9ad11d393c30f2839f43419e97a5a466d`.

## Independent replay and evidence verification

Re-ran `D74_pasteboard_source_trace.py` against the pinned historical and current checkouts. The replay JSON was structurally identical to the committed D74 JSON. All 10 historical and 8 current evidence entries had nonempty matched-line lists. The script derives each entry's Git blob OID, SHA-256, matched line numbers, and excerpts from the named pinned commit. The historical and current repo remotes and commit/tree IDs matched the report.

The old route is supported by the pinned interface code, client, proxy, stub registration/dispatch, NAPI entry, and concrete `PasteboardService::GetPasteData`. At the concrete read, the implementation derives a user ID, finds the clip, and copies its data. Search of the traced component route found no call to `PasteboardPermission::CheckSelfPermission` or `CheckCallingPermission`; the former returns `true` in the pinned snapshot, while the latter delegates to `MockPermission::VerifyPermission`. The report does not claim these helper bodies establish a platform authorization contract or that external policy is absent.

The historical `profile/3701.xml` declares SA name `3701`, library, and `distributed=false`; it has no caller ACL field. `profile/BUILD.gn` lists `3701.xml` as a source. The init config instead names `/system/profile/pasteboard_service.xml`. The checked-in source does not establish the install-time rename/copy mapping or resolve the external installed profile. D74 correctly identifies this as an evidence gap rather than treating the source profile as the complete installed policy.

For the separately pinned current source, `GetPasteDataInner` obtains the IPC caller token, evaluates `VerifyPermission(tokenId)`, and returns a permission error before `GetData(...)` when the check fails, except for the explicit developer-mode test-server path. `VerifyPermission` checks `READ_PASTEBOARD` and `SECURE_PASTE`; it also permits native/shell token types and the Ctrl+V path, and legacy SDK versions below the threshold fall through to `true`. An invalid SDK version returns false. These are checked source branches, not proof of AccessTokenKit behavior, product configuration, or a historical property.

## Assessment by area

- `fix-correctness`: PASS — D74 is documentation/evidence-only and its statements match the pinned excerpts reviewed.
- `candidate-retention`: PASS — D74 retains the narrow historical source observation and does not convert it into a product/CVE verdict.
- `coverage`: PASS WITH LIMITATIONS — both repository source paths and the stated old-profile/current-permission caveats are represented; external installed profile, generated IPC glue, platform permission manager, and product mapping are explicitly unresolved.
- `scope`: PASS — no implementation or fixture changes; evidence and conclusions stay within the pinned component snapshots.

## Second-layer prompt boundary

The downstream prompt names both repository commits and requires separate treatment, asks the reviewer to verify the historical call chain and cited identities, limits the conclusion to whether the pinned historical component shows an explicit caller check before its read, lists missing external evidence, and prohibits product safety/CVE-causality claims. It treats current source as a later implementation difference with exceptions. This is an appropriate review boundary.

## Remaining evidence needed for stronger claims

A stronger cross-layer or product determination would require the historical and current installed SA profiles plus platform SAMgr/ACL enforcement sources, AccessTokenKit/PermissionUtils implementation and policy, generated IPC source/build provenance, and a product manifest/image tied to one of the pinned commits. Until those are supplied, installed caller policy and product applicability remain unknown.
