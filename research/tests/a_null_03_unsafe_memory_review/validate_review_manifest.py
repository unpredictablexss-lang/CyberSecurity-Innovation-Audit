from __future__ import annotations

import argparse
import json
from pathlib import Path


DIMENSIONS = {
    "raw_observation_rows",
    "within_repository_root_cause_clusters",
    "cross_repository_identical_source_clusters",
    "human_review_outcomes",
}
DISPOSITIONS = {"confirmed", "not_reproduced", "not_testable", "safe_or_fixed", "known_false_positive", "unknown"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_manifest(manifest: dict) -> None:
    schema_version = manifest.get("schema_version")
    require(schema_version in {"ohscanner.a-unsafe-memory-stratified-review-v1", "ohscanner.a-unsafe-memory-stratified-review-v2"}, "unsupported schema_version")
    expected = manifest.get("expected_population")
    observed = manifest.get("observed_population")
    raw_rows = manifest.get("raw_observation_rows")
    sample_size = manifest.get("sample_size")
    require(all(nonnegative_int(value) for value in (expected, observed, raw_rows, sample_size)), "population and sample counts must be nonnegative integers")
    mismatch = expected != observed
    require(manifest.get("population_mismatch") is mismatch, "population_mismatch disagrees with expected/observed counts")
    require(manifest.get("provisional_frame") is mismatch, "provisional_frame must track population mismatch")
    require(raw_rows == observed, "raw_observation_rows must preserve every observed row")

    identity = manifest.get("observation_identity_audit")
    require(isinstance(identity, dict), "observation_identity_audit must be an object")
    rows, unique, duplicates = (identity.get(key) for key in ("rows", "unique_diagnostic_ids", "duplicate_diagnostic_id_rows"))
    require(all(nonnegative_int(value) for value in (rows, unique, duplicates)), "observation identity counts must be nonnegative integers")
    require(rows == raw_rows and unique <= rows and duplicates == rows - unique, "observation identity audit does not reconcile to raw rows")

    dimensions = manifest.get("report_count_dimensions")
    require(isinstance(dimensions, dict) and set(dimensions) == DIMENSIONS, "report_count_dimensions must contain exactly the four independent dimensions")
    raw = dimensions["raw_observation_rows"]
    require(isinstance(raw, dict) and raw.get("count") == raw_rows and raw.get("status") == "counted", "raw observation dimension must equal the preserved raw row count")

    roots = dimensions["within_repository_root_cause_clusters"]
    require(isinstance(roots, dict), "within-repository root-cause dimension must be an object")
    root_count, root_status = roots.get("count"), roots.get("status")
    if root_status == "not_established":
        require(root_count is None and isinstance(roots.get("reason"), str) and bool(roots["reason"].strip()), "unestablished root-cause count must be null with a reason")
    else:
        require(root_status == "counted" and nonnegative_int(root_count), "root-cause count must be counted or explicitly not established")

    cross = dimensions["cross_repository_identical_source_clusters"]
    require(isinstance(cross, dict), "cross-repository source dimension must be an object")
    cluster_count, cluster_rows = cross.get("count"), cross.get("rows_in_those_clusters")
    require(nonnegative_int(cluster_count) and nonnegative_int(cluster_rows), "cross-repository counts must be nonnegative integers")
    require(cluster_rows <= raw_rows and cluster_count * 2 <= cluster_rows, "cross-repository clusters must each contain rows from at least two repositories")
    require(cross.get("status") == "counted_from_source_bound_diagnostics", "cross-repository clusters require source-bound diagnostics")
    if schema_version == "ohscanner.a-unsafe-memory-stratified-review-v2":
        clusters = cross.get("clusters")
        require(isinstance(clusters, list), "v2 requires per-cluster source evidence")
        keys = set()
        for cluster in clusters:
            require(isinstance(cluster, dict), "cross-repository cluster evidence must be an object")
            rule_id, source_hash = cluster.get("rule_id"), cluster.get("source_sha256")
            repositories, row_count = cluster.get("repositories"), cluster.get("raw_observation_rows")
            require(isinstance(rule_id, str) and bool(rule_id.strip()), "cluster rule_id is required")
            require(isinstance(source_hash, str) and len(source_hash) == 64 and all(char in "0123456789abcdef" for char in source_hash), "cluster source_sha256 must be lowercase SHA-256")
            require(isinstance(repositories, list) and len(repositories) >= 2 and all(isinstance(repo, str) and bool(repo.strip()) for repo in repositories), "each cross-repository cluster must identify at least two repositories")
            require(len(repositories) == len(set(repositories)), "cluster repositories must be unique")
            require(nonnegative_int(row_count) and row_count >= len(repositories), "cluster raw rows must cover its distinct repositories")
            key = (rule_id, source_hash)
            require(key not in keys, "duplicate rule/source cluster evidence")
            keys.add(key)
        require(len(clusters) == cluster_count, "cluster evidence count does not match summary")
        require(sum(cluster["raw_observation_rows"] for cluster in clusters) == cluster_rows, "cluster evidence raw rows do not match summary")

    human = dimensions["human_review_outcomes"]
    require(isinstance(human, dict), "human review dimension must be an object")
    reviewed, pending, dispositions = human.get("reviewed"), human.get("pending"), human.get("disposition_counts")
    require(nonnegative_int(reviewed) and nonnegative_int(pending), "review counts must be nonnegative integers")
    require(reviewed + pending == sample_size, "reviewed plus pending must reconcile to sample_size")
    require(isinstance(dispositions, dict) and set(dispositions) <= DISPOSITIONS and all(nonnegative_int(value) for value in dispositions.values()), "disposition counts must use known labels and nonnegative integers")
    require(sum(dispositions.values()) == reviewed, "disposition counts must reconcile to reviewed rows")
    expected_status = "pending_independent_review" if reviewed == 0 else "reviewed" if pending == 0 else "partially_reviewed"
    require(human.get("status") == expected_status, "human review status disagrees with reviewed/pending counts")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate A-UNSAFE review manifest dimensions and count invariants.")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_manifest(manifest)
    print(json.dumps({"status": "valid", "manifest": str(args.manifest), "raw_observation_rows": manifest["raw_observation_rows"], "sample_size": manifest["sample_size"], "population_mismatch": manifest["population_mismatch"]}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"invalid review manifest: {error}") from error
