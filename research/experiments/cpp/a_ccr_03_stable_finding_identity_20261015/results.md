# A-CCR-03 Stable Finding Identity Experiment

- Generated: 2026-10-15T12:46:48.999057+08:00
- Reference model: `research/experiments/cpp/a_ccr_03_stable_finding_identity_20261015/identity_reference.py`
- Compatibility tests: 9/9 passed

## Synthetic compatibility matrix

| Case | Expected | Actual | Result |
|---|---|---|---|
| `insert_comment` | `persistent_moved_or_changed` | `persistent_moved_or_changed` | PASS |
| `message_change` | `persistent_changed_metadata` | `persistent_changed_metadata` | PASS |
| `move_expression` | `persistent_moved_or_changed` | `persistent_moved_or_changed` | PASS |
| `same_member_names` | `distinct_stable_identity` | `True` | PASS |
| `partial_failed_unknown` | `unknown_identity` | `{'partial': 'unknown_identity', 'failed': 'unknown_identity', 'unknown': 'unknown_identity'}` | PASS |
| `historical_v1` | `unbound_but_retained` | `{'stable_identity_status': 'unknown', 'occurrence_identity_status': 'unknown', 'source_binding': 'unbound', 'aliases': ['semgrep:historical-42']}` | PASS |
| `detector_rule_version` | `{'compatible': 'persistent_changed_metadata', 'unknown': 'unknown_version_boundary'}` | `{'compatible': 'persistent_changed_metadata', 'unknown': 'unknown_version_boundary'}` | PASS |
| `duplicate_anchors` | `unknown_identity_ambiguous` | `unknown_identity_ambiguous` | PASS |
| `observation_absence` | `observation_absent_comparable` | `observation_absent_comparable` | PASS |

## Existing fixed-scope rescan projection

- Input comparison SHA-256: `c7da13895f4ed08abf19eadefdea871c1633bf9a3f15833567034129a69d62e4`
- Current heuristic identity: `component|provider|rule_id|file|line|column|symbol|source_sha256`
- Counts: old 208 -> new 182; added 0 / disappeared 26 / changed 182 / unchanged 0
- Changed field sets: `{'diagnostic_id,message': 182}`
- Historical ID rows observed in projection: 208

### Interpretation

- All 182 retained rows changed only diagnostic_id and message under the current heuristic stable key.
- The 26 disappeared rows are unmatched under component|provider|rule_id|file|line|column|symbol|source_sha256; they are not security-truth disappearances.
- Existing comparison rows do not carry rule_lineage_id, AST fingerprints, Git byte ranges, or patch-region mappings, so proposed stable IDs cannot be reconstructed from this artifact alone.

## Boundary

- This experiment is proposal evidence only. It does not modify public contracts, runner, catalog, or analysis code.
- `disappeared`/`observation_absent_comparable` is an observation relation. `vulnerability_effect` remains `unknown`.
- No Precision/Recall or vulnerability promotion is computed.
