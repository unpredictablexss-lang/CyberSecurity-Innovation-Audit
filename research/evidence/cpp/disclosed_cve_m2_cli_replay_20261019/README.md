# Production CLI replay bundle

These tiny synthetic Git sources exercise the fetched M2 CLI's explicit `ohscanner.known_disclosed_cves` registration path. They are source-shaped controls, not copies of third-party source and not product snapshots.

Bundle SHA-256:

- `vulnerable-source.bundle`: `4b5f0cbc8aa414484e7777a73816c18de6b314671f94dfb8bcd29b4fada5c283` (commit `aaa265e33b497a26a638a2d79a68b3b8e0663e12`)
- `fixed-source.bundle`: `4feb3349d3a9dcde551247227be95848216485088d13b4a7f94e3c29a8322e0c` (commit `fb1309f75f13affdf8ca5c93ab88ba87704e4e49`)

To replay from the scanner worktree, clone either bundle to a temporary directory and use the commit shown in `../disclosed_cve_m2_cli_replay_20261019.json`:

```powershell
git clone research/evidence/cpp/disclosed_cve_m2_cli_replay_20261019/vulnerable-source.bundle tmp/disclosed-cves-vulnerable
git clone research/evidence/cpp/disclosed_cve_m2_cli_replay_20261019/fixed-source.bundle tmp/disclosed-cves-fixed
python -m src.cli ohscan-run --repo-dir tmp/disclosed-cves-vulnerable --repository fixture/disclosed-cves --commit aaa265e33b497a26a638a2d79a68b3b8e0663e12 --detector ohscanner.known_disclosed_cves --include png.c --include cJSON.c --include cJSON_Utils.c --json-out tmp/vulnerable.json --md-out tmp/vulnerable.md
python -m src.cli ohscan-run --repo-dir tmp/disclosed-cves-fixed --repository fixture/disclosed-cves --commit fb1309f75f13affdf8ca5c93ab88ba87704e4e49 --detector ohscanner.known_disclosed_cves --include png.c --include cJSON.c --include cJSON_Utils.c --json-out tmp/fixed.json --md-out tmp/fixed.md
```

The vulnerable report retains candidates and is blocked because one C file is parser-partial; the fixed control parses completely and is quiet. `validated_vulnerability` remains zero in both reports.
