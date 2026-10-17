# Local community scan validation

Scope: 12 repositories, 14412 source files, 177484384 bytes, 22/22 shards completed.

Coverage: 14406 UTF-8 analyzable files and 4129945 LOC. Non-UTF-8 files were retained as explicit not-analyzed rows. The scan emitted 57454 candidate diagnostics; these are not vulnerability counts.

The checkpoint completed every planned shard. One earlier UnicodeDecodeError was retried successfully and is retained as a resolved stale checkpoint entry, not a final failure.

The 15-day first-parent selection currently sees 12 endpoint commits across 12 local repositories. Ten repositories are shallow endpoint snapshots, so merge/cherry-pick replay coverage is incomplete.

This is local validation only. The full 514-repository run, upstream tree matching, deterministic second replay and final performance aggregation remain open.
