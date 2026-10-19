# C/C++ source-to-file-sink path traversal candidate method

Rule: `ohcpp-path-traversal-source-to-file-sink-candidate-001`, version `0.1.0`.

## Method

The bounded lexical prototype recognizes string-valued bucket/map extraction (`Get(key)` plus `std::get_if<std::string>`), local string-return and output-parameter summaries, up to 16 rounds of unique direct-call argument propagation, path/string assignments, and selected file APIs (`open`, `openat`, `fopen`, `unlink`, `remove`, `DeleteFile`, `RemoveFile`, `CreateFile`). A candidate is emitted at the sink when a source-derived string reaches it and no recognized basename/filename reduction or nearby explicit containment predicate is present.

This is a may-flow candidate rule. It does not prove that the field is attacker-controlled, that calls are reachable, that a guard dominates all paths, or that a filesystem operation crosses a security boundary. It does not model arbitrary aliases, virtual dispatch, macros, templates, path canonicalization, symlinks, or cross-translation-unit propagation. Unsupported relationships remain unknown. Parser `partial`, `failed`, and `not_run` never become safe negatives.

## Controls

The focused suite covers a cross-function vulnerable flow to `open` and `unlink`, a basename-reduced fixed-shaped flow, an explicit `starts_with` containment guard, unrelated logging APIs, no file sink, and partial parse retention. The fixed-shaped source is a synthetic control, not a verified upstream Contacts patch.

## Admission

The detector is intentionally not registered in shared Catalog by this lane. Production CLI selection is unavailable until Catalog ownership reviews and accepts the separate request in `research/deliveries/cpp/CONTACTS_PATH_TRAVERSAL_CATALOG_REQUEST_20261019.md`.
