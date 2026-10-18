# C4 exact snapshot dependency identity

This package defines the `ohscanner.ark-runtime-exact-snapshot-dependencies/v1` manifest and a read-only verifier. It binds the target source, 19 model source dependencies, six literal include candidates, two observed GN files, the C1 profile capture contract/tool, C2 semantic review, C3 replay/configuration evidence, and this verifier's source. It does **not** claim to be a complete compiler dependency closure.

## Recompute and verify

From the workspace root:

```powershell
python CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c4_20261018/dependency_manifest.py
```

The verifier reads raw bytes only. It does not run the compiler, a preprocessor, target build scripts, or change files. Exit code `0` means every input and profile field is bound and verified. Exit code `2` means blocked/unknown. The expected and observed summaries are returned separately so a changed or missing file cannot be mistaken for the frozen value. A report consumer may copy the returned `report_reference` object into a replay or Detector report; its `dependency_summary_sha256` is the shared identity field.

## Digest rules

- Raw file bytes are SHA-256 hashed before decoding; line endings and file names do not substitute for byte identity.
- Git-backed entries also check the Git blob SHA-1 framing (`blob <decimal length> NUL <bytes>`) against the recorded OID. Git OID and SHA-256 must both match.
- Manifest objects are encoded as UTF-8 JSON with lexically sorted object keys, compact separators, `ensure_ascii=false`, and non-finite numbers forbidden. Unicode is not normalized. Array order is significant; `inputs` are sorted by their ASCII `id`, and duplicate IDs are invalid.
- The digest covers source/profile metadata, ordered command arguments, macros, include paths, tool/parser versions, generated-dependency state, unresolved obligations, each input's content hash and provenance, and literal target include directives. Locator paths are canonical POSIX relative paths and are not treated as content proof.
- Verification recomputes the digest using observed input byte hashes. Missing inputs use a null observed hash and fail closed.

## Current result and limits

The manifest is intentionally `blocked`. C3's report records `light-ast`, `build_profile=none`, `macro_expansion=false`, and a partial parse. The supplied C1 evidence binds source/environment identity but has no accepted product compile profile or compile database. The target's six literal include directives are inventoried; without the accepted include search order, their active transitive closure and generated headers cannot be established. Compiler/preprocessor binaries, parser artifact bytes, product macros, target platform, and generated build inputs therefore remain unbound. The missing C2 case matrix referenced by `replay.py` is also recorded as a blocker rather than copied from another worktree.

The 39 listed raw-byte inputs currently recompute to:

`6aba13c03d071edb4e07076a5e1910d631903c95755691c4e068ed4d27a653a9`

The six direct quoted includes and two GN files have byte hashes, but their Git blob identities/compiler resolution are not confirmed in this host; the verifier reports them as untrusted origins. The only `args.gn` found is under the separate OpenHarmony 5.0.2 output tree; that build attempt failed before Ark Runtime compilation and does not establish this target's profile. The C1 capture contract is bound from the C3 review worktree, where its exact snapshot record is explicitly `blocked` with no compile database and a null profile digest. C2's 18 changed dependencies remain unknown/blocked. This value is a deterministic inventory digest, not a trusted preprocessor cache key while status is blocked. `report_binding.v1.json` associates immutable C3 report hashes from both review worktrees with this same digest as a retrospective reference; it does not alter or upgrade those historical runs. Do not package or copy `research/evidence/ark_runtime/`; this package contains none of its admin-only material.
