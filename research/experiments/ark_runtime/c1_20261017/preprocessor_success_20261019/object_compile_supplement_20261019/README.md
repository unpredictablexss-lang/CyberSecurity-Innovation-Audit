# Supplemental direct object compilation — 2026-10-19

Both preserved ARM compile commands for `hihope/rk3568` were invoked directly through the pinned OHOS Clang 15.0.4 binary. Both returned 0 and produced object files:

| Action | Result | Object SHA-256 |
|---|---:|---|
| `libark_jsoptimizer_set` | 0 | `87085144abb1566909828f00ead2602c7738fae3f70c7c6b4dfe354f6b5c6831` |
| `libark_jsoptimizer_set_with_maple` | 0 | `b4d24b2db363bf88b4768c3194e12bbda3ffeba8fad0671e5308495e8695a19a` |

The driver `../run_profile_object_compile_20261019.py` invokes only these two commands with `shell=False`, redirecting `-o` and `-MF` to this evidence directory. It does not invoke GN, Ninja, build scripts, or a linker. The source view is a symlink farm, and the source archive itself was not changed by the driver. Full argv, compiler hashes, return codes, dependency files, stderr, and output hashes are recorded in `object_compile_observation.v1.json`.

## Evidence boundary

This is supplemental compiler evidence only. It ran as an unprivileged WSL process, outside the original no-network container with read-only source/toolchain mounts; read-only source access was not enforced by a mount. It does not establish a clean Ninja graph, a reproducible in-boundary object build, a product image build, or completeness of the source snapshot. The duplicate-output warnings, 19 nested gitlink commit trees outside the manifest archive, and missing `vendor/ohemu/common/qemu-run` linkfile source remain unresolved, so the C1 product-build gate remains blocked.
