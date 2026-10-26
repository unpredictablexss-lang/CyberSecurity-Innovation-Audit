# T1 upstream source verification evidence

All network queries in this folder target official OpenHarmony GitCode repositories and inspect source objects only; the PoC executions remain offline in Docker.

## Contacts refs

- Repository: `https://gitcode.com/openharmony/applications_contacts_data.git`
- `remote_refs.txt` records selected `refs/heads/*` tips observed on 2026-10-19.
- `release_tag_refs.txt` records the exact release tag object IDs observed with `git ls-remote --tags`.
- `release_tag_audit.json` dereferences annotated tags to commit/tree, computes the Contacts source blob SHA-1/SHA-256/size, and searches the complete snapshot for `PortraitFileName`, `portraitFileName`, and `DeleteFile(srcFilePath)`.
- `snapshot_audit.json` separately checks the named branch tips; do not conflate branch tips with release tags.
- `history_audit.json` records the first exact source marker in current master history, relevant later source-touch commits, source function hash, and tag ancestry. Current master history was unshallowed for this check; the temporary object database was removed after writing the evidence.

## Pinned A0 sources and permission manifest

- `source_objects_audit.json` re-fetches the A0 Contacts commit `341cc3bf41b48e9a5f278dd088f40a2041d2f1c9` and DataShare commit `560c5cdadf08b4beeb691e93d70ff32cc2dca8bd`, then verifies each of the eight pinned source files against A0 blob ID, SHA-256, and size.
- The same record compares `services/accesstokenmanager/permission_definitions.json` at AccessToken pin `fe40d5e6c19071c29916903c777f168b2b85e404` and current master `f811ac9fcebe948bff04e03a2af68929e6309976`.

## Reproduction outline

1. Run `git ls-remote --heads` and `git ls-remote --tags` against the URLs above; compare outputs with the two refs text files.
2. In a disposable bare repository, fetch exact branches and tags at depth one. Fetch the full Contacts `master` history before running `git log --all -G 'groupPath \\+ portraitFileName|DeleteFile\\(srcFilePath\\)' -- dataBusiness/contacts/src/contacts_data_ability.cpp`.
3. For every source row, use `git rev-parse <commit>:<path>` for the blob and `git show <commit>:<path>` piped as raw bytes to SHA-256; do not hash CRLF working-tree files.
4. Remove the disposable bare repository after recording results; it is not part of the delivery.

The exact fetched commits, trees, blob IDs, source hashes and observations are in the adjacent JSON artifacts.
