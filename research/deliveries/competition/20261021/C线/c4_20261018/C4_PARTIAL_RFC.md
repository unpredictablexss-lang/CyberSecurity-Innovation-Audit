# C4 exact-source partial-result path

This branch adds an experimental path for the two exact upstream snapshots in `RuntimeTypeModel.target_bindings`. Catalog marks the detector `research_candidate`, excludes it from defaults, and permits explicit selection. Its Runner applicability selector scopes it to the bound repository and source path. The adapter then requires Git-object provenance, a full bound commit, the `light-ast` profile, exact Git blob and SHA-256, and consistent shared AST parse status.

The adapter invokes the bounded local analyzer for a partial unit only after these checks. The candidate remains local evidence with `parse_completeness_impact`; the per-file outcome stays partial and the detector run stays blocked. Runner coverage keeps the candidate and obligation visible without converting partial into complete or safe. Selector exceptions and out-of-scope returns fail only that detector closed and leave other detectors running.

This is an experimental, exact-binding bridge using existing v2 coverage and evidence-obligation fields. It is not a general partial-AST policy, and it does not prove that omitted declarations, macros, includes, overloads or build flags cannot contaminate the target body. The model still carries an unverified product build-profile assumption. Independent owner review must approve the route before broader use.
