from pathlib import Path
p=Path("research/experiments/ark_runtime/c10_ark_gap_rules_20261019/replay_real_sources.py")
s=p.read_text(encoding="utf-8")
s=s.replace('''    actual = {
        "commit": commit,
        "path": path,
        "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0)) + raw).hexdigest(),
        "sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    actual["matches_model"] = (actual["git_blob_sha1"] == row[2] and actual["sha256"] == row[3])
''', '''    resolved_blob = subprocess.check_output(
        ["git", "rev-parse", f"{commit}:{path}"], cwd=ARK, text=True).strip()
    stream_blob = sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0)) + raw).hexdigest()
    actual = {
        "commit": commit,
        "path": path,
        "git_blob_sha1": resolved_blob,
        "stream_blob_sha1": stream_blob,
        "stream_blob_matches_resolved_object": stream_blob == resolved_blob,
        "sha256": sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    actual["matches_model"] = (resolved_blob == row[2] and actual["sha256"] == row[3])
''')
p.write_text(s,encoding="utf-8",newline="")
print("patched identity evidence")
