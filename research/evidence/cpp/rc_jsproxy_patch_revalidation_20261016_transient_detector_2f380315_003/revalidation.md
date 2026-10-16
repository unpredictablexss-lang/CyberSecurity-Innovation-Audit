# RC-JSPROXY patch revalidation

- Generated: `2026-10-16T03:46:42.964782Z`
- Status: `candidate/unknown`; `validated_vulnerability=0`; `confirmed/reportable=false`.
- Overall outcome: `stable_reproduced_and_patch_revalidated`.
- Patch SHA-256: `3b04fd4e5575e224df35f77be487f3cd90d0a40501b1ff65f5d01886037124c9`.

## Identity

- OHScanner HEAD: `993cfdc21877440f5d4a4ad345ee9ec236e098fa`
- OHScanner tree: `5d228d0d895f29acfc841191f4f9a5167356cc3e`
- Target HEAD: `acfb22aac16161d8fb0cefb6cc9b92f04f489a80`
- Target tree: `3b92c53fde616d5a3f9487b0c295670a42c63023`
- Target source blob: `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46`
- Target source SHA-256: `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`

## Toolchain

- Compiler: `/usr/lib/llvm-14/bin/clang`
- Compiler SHA-256: `31925065812631303cf9af9a30b2f56427d2102667a87a9fb4ba03a306104589`
- Sanitizer: ThreadSanitizer (`-fsanitize=thread`), `TSAN_OPTIONS=halt_on_error=1:exitcode=66`.
- GNU time: `/usr/bin/time`.

## Variant replays

| variant | mode | repeat | wall s | peak RSS KiB | exit | trigger | status | failure reason |
|---|---|---:|---:|---:|---:|---|---|---|
| `vulnerable` | `single` | 1 | 0.020 | 19388 | 0 | `clean` | `passed` | none |
| `vulnerable` | `single` | 2 | 0.020 | 19388 | 0 | `clean` | `passed` | none |
| `vulnerable` | `single` | 3 | 0.020 | 19388 | 0 | `clean` | `passed` | none |
| `vulnerable` | `race` | 1 | 0.050 | 21408 | 66 | `sanitizer_triggered` | `passed` | none |
| `vulnerable` | `race` | 2 | 0.050 | 21664 | 66 | `sanitizer_triggered` | `passed` | none |
| `vulnerable` | `race` | 3 | 0.050 | 21408 | 66 | `sanitizer_triggered` | `passed` | none |
| `vulnerable` | `close_get_entry` | 1 | 0.050 | 20512 | 66 | `sanitizer_triggered` | `passed` | none |
| `vulnerable` | `close_get_entry` | 2 | 0.050 | 20384 | 66 | `sanitizer_triggered` | `passed` | none |
| `vulnerable` | `close_get_entry` | 3 | 0.040 | 20384 | 66 | `sanitizer_triggered` | `passed` | none |
| `vulnerable` | `unrelated` | 1 | 0.030 | 21308 | 0 | `clean` | `passed` | none |
| `vulnerable` | `unrelated` | 2 | 0.030 | 21308 | 0 | `clean` | `passed` | none |
| `vulnerable` | `unrelated` | 3 | 0.030 | 21308 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `single` | 1 | 0.020 | 19368 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `single` | 2 | 0.020 | 19368 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `single` | 3 | 0.020 | 19368 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `race` | 1 | 0.320 | 25116 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `race` | 2 | 0.380 | 25116 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `race` | 3 | 0.360 | 24988 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `close_get_entry` | 1 | 0.600 | 21788 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `close_get_entry` | 2 | 0.580 | 21788 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `close_get_entry` | 3 | 0.590 | 21916 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `unrelated` | 1 | 0.030 | 21288 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `unrelated` | 2 | 0.030 | 21288 | 0 | `clean` | `passed` | none |
| `fixed_control_mutex` | `unrelated` | 3 | 0.030 | 21288 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `single` | 1 | 0.020 | 19376 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `single` | 2 | 0.020 | 19376 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `single` | 3 | 0.020 | 19376 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `race` | 1 | 0.300 | 25124 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `race` | 2 | 0.320 | 24868 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `race` | 3 | 0.290 | 25124 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `close_get_entry` | 1 | 0.580 | 21668 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `close_get_entry` | 2 | 0.590 | 21724 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `close_get_entry` | 3 | 0.610 | 21796 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `unrelated` | 1 | 0.030 | 21296 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `unrelated` | 2 | 0.030 | 21424 | 0 | `clean` | `passed` | none |
| `patched_atomic_minimal` | `unrelated` | 3 | 0.030 | 21424 | 0 | `clean` | `passed` | none |

## Controls

- Positive/fixed/safe/unrelated A-line matrix: `20/20` passed.
- Native controls: `20/20` passed.
- Unknown obligations retained: `3` controls with `synchronization_proof=unknown`.
- Zero-fuzz repair controls: `6/6` passed.
- Control suite wall/RSS: `85.19` s / `125448` KiB.

## Patch revalidation boundary

The patch removes the modeled `JSProxy` owner data race and preserves the controlled single-thread functional sequence. It does not prove product-level fix correctness, performance neutrality, full result-set protocol safety, affected branches/versions or CIA impact. The candidate remains `candidate/unknown`; no CVE is assigned.

