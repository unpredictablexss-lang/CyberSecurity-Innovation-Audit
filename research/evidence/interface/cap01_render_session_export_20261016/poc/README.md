# CAP-01 PoC component model

This directory contains a runnable source-bound model of the selected CAP-01 dispatch path. It is not a
product build and cannot promote the candidate.

## Container-only rule

`run_poc.py` refuses to build or run unless both are true:

- `OHSCANNER_VALIDATION_CONTAINER=1`
- `/.dockerenv` exists

Do not weaken this check. A resource-limited host subprocess is not a PoC sandbox.

## Exact isolated run

Prepare an output directory and run the existing project validation image:

```bash
docker image inspect ohscanner-validation:local --format '{{.Id}}'
docker run --name ohscanner-cap01-validation \
  --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --pids-limit 64 --memory 2048m --cpus 2 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
  --mount "type=bind,src=$PWD/research/evidence/interface/cap01_render_session_export_20261016,dst=/opt/cap01,readonly" \
  --mount "type=bind,src=/path/to/window_window_manager,dst=/input/target,readonly" \
  --mount "type=bind,src=/path/to/cap01-output,dst=/work" \
  -e OHSCANNER_VALIDATION_CONTAINER=1 \
  -w /opt/cap01 ohscanner-validation:local \
  python /opt/cap01/poc/run_poc.py \
    --target /input/target \
    --out /work/validation-result.json \
    --repeats 3
```

The target directory must contain the pinned local Git objects for commit
`8b0d8fe1b973d865904c942c286b3d2a3b9b08e7`. Its dirty working-tree bytes are ignored.

## What the runner does

1. Verifies full commit and tree.
2. Verifies 10 source Git blobs and SHA-256 values.
3. Verifies 18 quoted source relations at exact line numbers.
4. Builds `vulnerable`, `fixed_control`, and `patched` variants.
5. Uses `-std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer`.
6. Runs four scenarios per variant and repeat:
   `unauthorized_export`, `authorized_export`, `wrong_descriptor`, `unknown_screen`.
7. Writes commands, stdout/stderr, compiler identity, binary hashes and match results to
   `validation-result.json`.

Expected modeled behavior:

| Variant | unauthorized | authorized | wrong descriptor | unknown screen |
|---|---:|---:|---:|---:|
| vulnerable | export | export | deny | deny |
| fixed_control | deny | export | deny | deny |
| patched | deny | export | deny | deny |

## What success does not prove

Even if all three variants replay cleanly with ASan/UBSan, the result is only a controlled component model.
It does not establish real OpenHarmony product reachability, permission enforcement, attacker identity,
render-session capabilities, CIA impact, affected releases, or exploitability. Product evidence must be
collected separately and passed through a fail-closed promotion review.