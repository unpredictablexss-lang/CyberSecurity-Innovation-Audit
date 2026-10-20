# D15 AccessToken identity logging replay

Date: 2026-10-18

## Scope and provenance

One-file offline research replay against `openharmony/security_access_token`, pinned to commit `3be426c558613e7c7af92a591c2bfaeb6af06b60`, tree `40a7fbc8f09dee1e965ce0d68157fd1dafd2df7f`. Target blob: `75bc67ca0836b3d5dfca70e3cab6be128ca9f8aa`; SHA-256: `c702336c933dfe3ac5aaba4ee27e3268230a96446681083c490d04d744c6b549`. The repository was cloned to a temporary local mirror; no third-party source was copied into this repository.

The exact replay is recorded in [D15_ACCESS_TOKEN_REPLAY.json](D15_ACCESS_TOKEN_REPLAY.json) and can be repeated with:

```sh
/tmp/ohscanner-d-venv/bin/python research/data_sensitive/d15_access_token_replay.py \
  --local-git-store /tmp/ohscanner-extra-sources/security_access_token \
  --commit 3be426c558613e7c7af92a591c2bfaeb6af06b60 \
  --output research/data_sensitive/D15_ACCESS_TOKEN_REPLAY.json
```

The script reads one exact Git blob and does not call the public Runner, fetch source, or claim repository-wide coverage.

## Observation

The detector retained five direct log candidates at lines 784, 791, 819, 831 and 834, plus three unresolved cross-component call candidates at lines 785, 797 and 859. The direct logs are explicit in the pinned file: `GetKernelPermissions` logs `tokenID` as public at line 784; `SetPermissionStatusWithPolicy` logs it at lines 831 and 834. The model treats AccessTokenID/FullTokenID as authorization identities, not bearer secrets. The replay is `blocked`, and the target file is `partial`.

All eight results remain candidates with unresolved obligations. This does not establish unauthorized log readership, sensitive-data policy violation, exploitable product entry, concrete impact, or a vulnerability. `validated_vulnerability=0`. The three unresolved calls are retained because the detector does not resolve their implementations across component boundaries.

## Limits and next evidence

This is one target file and one exact revision, not a full component scan or independent holdout. There is no recall/precision claim. Two fresh offline reruns reproduced the same eight candidate identities, source hash, and obligations; the comparison is recorded in `D15_REPEAT_STABILITY.json` and does not constitute an independent holdout. The current parser has partial coverage, no preprocessor/build configuration, no full interprocedural or alias proof, and no runtime log visibility or product entry evidence. The result is a source/sink model integration experiment; it is not a product finding, PoC, or fix recommendation.

Before integrating this profile, add fixed/safe/unrelated controls and an independently labelled sample set, assess whether public token identifiers violate the product privacy model, and improve C++ parsing/coverage. Do not promote the profile to general Catalog/default scanning based on this experiment.
