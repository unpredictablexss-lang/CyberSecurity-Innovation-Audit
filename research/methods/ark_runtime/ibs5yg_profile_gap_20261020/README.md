# IBS5YG product profile evidence gap

**Disposition: `BLOCKED`.** The local evidence does not bind IBS5YG's frozen parent/fix pair to a shipped product build or preprocessing environment. This is an evidence inventory, not a product vulnerability or safety conclusion.

The machine-readable evidence matrix is [`evidence_matrix.json`](evidence_matrix.json). It records each artifact path, SHA-256, identity context, direct claim, and limitation. The IBS5YG source pair is independently resolvable in the local bare Git store: commit/tree/path blob IDs, byte lengths, and source SHA-256 values match the profile manifest, and the fixed commit is a child of the parent. The store's configured Gitee origin is self-reported; acquisition and custody are not independently attested.

The 5.0.2 artifacts do not close IBS5YG. The only `args.gn` in the inspected `ark-runtime-isolated-validation-20261018` output belongs to the Sort/CVE-2025-23420 attempt. That attempt records `ark_js_host_linux_tools_packages`, failed before Ark Runtime compilation, and has no successful product binary or image. Its runtime component pin `1b23531531e768398682582969c2a9f17e72cafe` is the Sort cherry-pick; neither IBS5YG commit is an ancestor of it. The unrelated C1 ARM preprocessing actions likewise use a different Ark Runtime source SHA and a failed Ninja target, so they are excluded.

Missing IBS5YG evidence includes a locked shipped-product manifest and component revision, successful GN target/action plus exact `args.gn`, target compiler/linker/sysroot, compile database and complete include/generated-input closure, hashed preprocessed TU and macro log, successful compile/link logs, and a source-to-shipped binary/image mapping. Product/build/preprocess owners must supply these artifacts. The current case remains blocked until each required link refers to the same product release and source identity.

## Independent T4 handoff

T4 independently confirmed the frozen source identity and ancestry, confirmed that the 5.0.2 component pin is not IBS5YG, and excluded the Sort host-tools arguments/build artifacts. T4's final review should recompute the hash of `evidence_matrix.json` and record claim-level dispositions in its ownership-scoped `review/` directory. Any counterexample must be returned to D4 and reflected in the matrix before this assessment is finalized.
