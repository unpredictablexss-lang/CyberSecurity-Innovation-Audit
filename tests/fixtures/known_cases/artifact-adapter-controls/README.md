# Artifact adapter controls

These fixtures are synthetic and bounded.

- `OpenHarmony.p12` is an 8-byte DER-envelope marker only. It contains no key, certificate, password, trust material, or real signing identity.
- `build-profile.json5` is a synthetic configuration-shape control.
- `security_asset.rs` is a synthetic Rust language-scope control.

The adapters only identify artifact/language boundaries and emit explicit unknown limitations. They do not parse signing semantics or establish product inclusion.
