# IBS5YG D5 intake gate

This directory contains a structural intake schema, a fail-closed checker, and
a synthetic self-test. It does not fill any real product field. The original
`D5_PRODUCT_TARGET_INTAKE_20261020.json` remains the record of current owner
inputs.

## Contract

Each of the six target identity fields is represented as `{value, evidence}`.
Each evidence entry names a nonempty issuer string, a safe relative path below
an explicitly supplied evidence root, the SHA-256 of the referenced bytes,
and a declared `build_identity` containing all six fields. The checker requires
every declared build identity to match and each field value to equal its
corresponding identity value. The locked-manifest field accepts a 40/64-hex
immutable commit (optionally prefixed `commit:`) or an HTTPS URI carrying one
64-hex SHA-256 in its query or fragment. A mutable branch URL by itself is
rejected. For a URI, the locked-manifest field's evidence path must point to
the local manifest bytes, and its URI SHA-256 must equal both the evidence
reference hash and a fresh hash of those bytes. For a commit reference, the
commit must exist in the local Git object database reachable from the supplied
evidence root, and `git cat-file commit` bytes must equal the referenced file.
These checks use no network. An absent local manifest or commit is blocked;
the checker does not fetch URLs.

Any missing field or evidence item, unsafe/missing path, reparse-point or
symlink component, unreadable file, incorrect digest, missing issuer, or
conflicting identity returns `WAITING_OR_BLOCKED` and exit code 2. When the
structure is complete it returns
`STRUCTURE_COMPLETE_REQUIRES_INDEPENDENT_REVIEW`, never `READY`, with
`admission_ready: false` and exit code 0. Hashing proves only which bytes were
read. It does not establish that those bytes support the claim, that an issuer
is genuine or authorized, that custody is valid, or that a product actually
uses the asserted build. A URI digest match is only a local byte-identity
check; it does not prove that the URL is reachable or that the bytes were
downloaded from it. Local Git object presence likewise does not prove custody
or product association.

## Reproduce

From the repository root with Python 3.10 or later:

```powershell
python research/methods/ark_runtime/ibs5yg_profile_gap_20261020/intake/validate_intake.py --self-test
python research/methods/ark_runtime/ibs5yg_profile_gap_20261020/intake/validate_intake.py --manifest <intake.json> --evidence-root <evidence-root>
```

The bundled `blocked-example.json` deliberately has six null fields. Running
it should report `WAITING_OR_BLOCKED` and exit code 2:

```powershell
python research/methods/ark_runtime/ibs5yg_profile_gap_20261020/intake/validate_intake.py --manifest research/methods/ark_runtime/ibs5yg_profile_gap_20261020/intake/blocked-example.json --evidence-root research/methods/ark_runtime/ibs5yg_profile_gap_20261020/intake
```

The self-test builds temporary synthetic evidence and checks a structurally
complete control plus missing values, missing issuer, byte tampering, path
traversal, absolute paths, missing files, identity conflicts, a mutable
manifest reference, and a symlink or junction escape when the host permits
creating one. It also rejects URI digests that do not match the referenced
local bytes, an unresolved URI with no matching local bytes, and commit IDs
without a locally resolvable matching object. Synthetic success is not product
evidence and must not change PC-1, PC-3, or admission status.
