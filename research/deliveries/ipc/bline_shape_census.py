"""Text census of the API shapes the four new rules key on, over 54 components.

This is an upper bound on sites, not reachability: it counts source text in the
same file set the pinned driver scans. Its job is to separate "the shape is not
in this corpus" from "the shape is here and the walk did not reach it".
"""
import argparse, collections, json, os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bline_direct_measure as M

ROOTS = ['/home/audit/openharmony-audit/perf-corpus', '/home/audit/corpus-ipc-widen',
         '/home/audit/corpus-ipc-shape', '/home/audit/corpus-ipc-bline',
         '/home/audit/corpus-ipc-extra', '/home/audit/corpus-ipc-batch3']

PATTERNS = {
    'ReadRawData': re.compile(r'\bReadRawData\s*\('),
    'ReadBuffer': re.compile(r'\bReadBuffer\s*\('),
    'ReadInt32': re.compile(r'\bReadInt32\s*\('),
    'ReadString': re.compile(r'\bReadString\s*\('),
    'Reuse': re.compile(r'\.\s*Reuse\s*\(|->\s*Reuse\s*\('),
    'RewindRead': re.compile(r'\bRewindRead\s*\('),
    'SetReadPosition': re.compile(r'\bSetReadPosition\s*\('),
    'Seek': re.compile(r'\.\s*Seek\s*\(|->\s*Seek\s*\('),
    'ResetCallingIdentity': re.compile(r'\bResetCallingIdentity\s*\('),
    'ResetCallingIdentity_bare': re.compile(
        r'^[ \t]*(?:\w+::)?ResetCallingIdentity\s*\(\s*\)\s*;', re.M),
    'SetCallingIdentity': re.compile(r'\bSetCallingIdentity\s*\('),
    'GetCallingUid': re.compile(r'\bGetCallingUid\s*\('),
    'GetCallingTokenID': re.compile(r'\bGetCallingTokenID\s*\('),
}


def git(repo, *args):
    return subprocess.run(['git', '-C', repo, *args], capture_output=True,
                          text=True, check=True).stdout.strip()


def targets():
    seen = {}
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            d = os.path.join(root, name)
            if os.path.isdir(os.path.join(d, '.git')) and name not in seen:
                seen[name] = d
    return sorted(seen.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    rows = []
    for name, repo in targets():
        commit = git(repo, 'rev-parse', 'HEAD')
        counts = collections.Counter()
        files = collections.Counter()
        for path, mode, kind, oid in M.tree(repo, commit):
            ok, why = M.eligible(path, mode, kind)
            if not ok:
                continue
            data = M.git(repo, 'cat-file', 'blob', oid)
            if len(data) > M.MAX_BYTES:
                continue
            try:
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                continue
            for key, pattern in PATTERNS.items():
                found = len(pattern.findall(text))
                if found:
                    counts[key] += found
                    files[key] += 1
        row = {'component': name, 'commit': commit, 'counts': dict(counts),
               'files': dict(files)}
        rows.append(row)
        print(name, json.dumps(dict(counts)), flush=True)
        json.dump(rows, open(os.path.join(a.out, 'census.json'), 'w'), indent=2)
    total = collections.Counter()
    for row in rows:
        total.update(row['counts'])
    print(json.dumps({'components': len(rows), 'totals': dict(total)}, indent=2))
    json.dump({'components': len(rows), 'totals': dict(total), 'rows': rows},
              open(os.path.join(a.out, 'census.json'), 'w'), indent=2)


if __name__ == '__main__':
    main()
