# RC-JSPROXY patch revalidation

- Generated: `2026-10-16T03:33:15.163832Z`
- Status: `candidate/unknown`; `validated_vulnerability=0`; `confirmed/reportable=false`.
- Overall outcome: `revalidation_incomplete_or_failed`.
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

## Controls

- Positive/fixed/safe/unrelated A-line matrix: `20/20` passed.
- Native controls: `3/20` passed.
- Unknown obligations retained: `3` controls with `synchronization_proof=unknown`.
- Zero-fuzz repair controls: `6/20` passed.
- Control suite wall/RSS: `None` s / `None` KiB.

## Patch revalidation boundary

The patch removes the modeled `JSProxy` owner data race and preserves the controlled single-thread functional sequence. It does not prove product-level fix correctness, performance neutrality, full result-set protocol safety, affected branches/versions or CIA impact. The candidate remains `candidate/unknown`; no CVE is assigned.

