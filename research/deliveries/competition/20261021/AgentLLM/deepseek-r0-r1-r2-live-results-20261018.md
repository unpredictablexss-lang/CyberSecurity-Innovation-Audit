# DeepSeek live R0/R1/R2 experiment — 2026-10-18

## Scope and binding

This was an explicitly authorized live-provider workflow experiment against the user's existing R0 record. The R0 record was not edited. Experiment: `r0-ipc-access-token-20261018-r2-retry6`; paired operations: R1 `f432a6fe3a814f67868932f919a37608`, R2 `4a360965fda747b7acc5358f4e0b5ef0`. Tool policy: `readonly-fixed-commit-0.6.2`.

The fixed source is `openharmony/security_access_token` at commit `17d88bfb36bea6c9370ba919ac41a22d16dd66b3`, file `interfaces/innerkits/accesstoken/src/accesstoken_callback_stubs.cpp`, source SHA-256 `a0b148f9f0f1f06344477a9e3309c3efaa81b8b2d89be00a25f794ce66243340`. The live candidate ID is `66d4ac577163cbc8ae4b6eb088fcf7cdf3eda9d24e38e0d86d323eafbed922f1`; the job ID is `2b74c1ae859a47fb9e824c7d70731596`.

## Results

| Arm | Provider result | Server disposition | Usage |
|---|---|---|---|
| R1 | One bounded model call completed. One structured source-related claim was accepted, citing exact lines 94–98 inside the candidate function. Three of four evidence obligations remained unresolved. | `completed_with_limitations`; assessment `unknown`; citation presence/range validated, semantic support not machine-verified. | 2,818 input + 800 output = 3,618 tokens |
| R2 | The final structured answer and one bounded repair both failed JSON validation (`invalid_json`). | Server discarded the model answer and failed closed: zero retained claims, all four obligations unresolved, assessment `unknown`; `completed_with_limitations`. | 12,169 input + 317 output = 12,486 tokens |

Combined usage was 14,987 input + 1,117 output = 16,104 tokens. Provider-reported cost was unavailable. R2 used three model calls total. The raw rejected response body is not in the result record; only safe validation codes and response-shape counters are retained.

## Evidence boundary

Both arms preserve `vulnerability_state=candidate` and `validated_vulnerability=0`. R1 supports only the narrow observation that the cited source contains an `IsAccessTokenCalling()` guard which returns on failure. It does not establish what that helper authorizes, whether the candidate is reachable in a product build, attacker control, or impact. R2 contributes no accepted model claims. Neither result confirms or refutes a product vulnerability, establishes model quality, or proves citation entailment.

Next useful evaluation steps are independent blinded human review of the accepted R1 citation and a small compatibility set for R2 structured output, followed by product/build reachability evidence. Keep the original R0 and this run immutable; do not promote from these outputs.

## Runtime verification

The isolated 18776 service root and built application script both returned HTTP 200 during finalization. No push, merge, or Draft status change was performed. The live service process predates the latest response-shape diagnostic source edit; the experiment results above were produced before that diagnostic-only edit.

Follow-up liveness check: the browser tab still showed cached experiment rows but its API displayed `Failed to fetch`; `curl http://127.0.0.1:18776` was refused, and the former temporary OHSCANNER_DATA directory was absent. This does not invalidate the recorded completed operation results, but they cannot be re-opened in the current service instance. No replacement database or Provider configuration was created.
