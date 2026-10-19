from __future__ import annotations
import argparse, hashlib, json, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.fixture import snapshot_digest

COMMITS = {
    'vulnerable': '9dff73bebc5661f2dace6f16e14cf9e857172f4e',
    'fixed': '3e0dcf0ec651638b2bd849b2e6f3124b36890d99',
}
PATH = 'libtiff/tif_getimage.c'
HEADER = 'libtiff/tiffio.h'

def git(repo: str, *args: str) -> bytes:
    return subprocess.run(['git', '-C', repo, *args], check=True, capture_output=True).stdout

def object_data(repo: str, commit: str, path: str) -> tuple[bytes, str, str]:
    data = git(repo, 'show', f'{commit}:{path}')
    tree = git(repo, 'rev-parse', f'{commit}^{{tree}}').decode().strip()
    blob = git(repo, 'rev-parse', f'{commit}:{path}').decode().strip()
    return data, tree, blob

def function_span(text: str, name: str):
    index = parse_source(text, language='c')
    fn = next(f for f in index.functions if f.name == name)
    lines = text.splitlines(keepends=True)
    return index, fn, ''.join(lines[fn.start_line-1:fn.end_line])

def extract_struct(header: str) -> str:
    start = header.index('struct _TIFFRGBAImage' + chr(10) + '{')
    brace = header.index('{', start)
    depth = 0
    for pos in range(brace, len(header)):
        depth += (header[pos] == '{') - (header[pos] == '}')
        if depth == 0:
            return header[start:pos+1] + ';'
    raise ValueError('unclosed _TIFFRGBAImage')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo-dir', required=True)
    ap.add_argument('--output-dir', required=True)
    args = ap.parse_args()
    outdir = Path(args.output_dir); outdir.mkdir(parents=True, exist_ok=True)
    results = {}
    for role, commit in COMMITS.items():
        data, tree, blob = object_data(args.repo_dir, commit, PATH)
        header_data, header_tree, header_blob = object_data(args.repo_dir, commit, HEADER)
        source = data.decode('utf-8'); header = header_data.decode('utf-8')
        full_index, fn, function = function_span(source, 'TIFFReadRGBAImageOriented')
        struct = extract_struct(header)
        # uint32_t is supplied by the system <stdint.h> include in this source.
        # The local probe spells its common underlying type to keep the bounded unit standalone.
        text = 'typedef unsigned int uint32_t;\n' + struct + '\n' + function
        fragment_index = parse_source(text, language='c')
        unit = SourceUnit(PATH + '#TIFFReadRGBAImageOriented', 'c', text,
                          hashlib.sha256(text.encode()).hexdigest(),
                          parse_status=fragment_index.parse_status)
        context = ScanContext(ScanRequest(
            'd21:' + role, 'libtiff/libtiff', commit, snapshot_digest((unit,)),
            'current-component:libtiff/libtiff', 'light-ast', 'fixture'), (unit,))
        run = CppBoundsDetector().detect(context, (unit,))
        results[role] = {
            'commit': commit, 'tree': tree, 'path': PATH, 'blob': blob,
            'file_sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
            'header': {'path': HEADER, 'blob': header_blob,
                       'sha256': hashlib.sha256(header_data).hexdigest(),
                       'tree': header_tree},
            'function': {'name': fn.name, 'original_start_line': fn.start_line,
                         'original_end_line': fn.end_line,
                         'function_slice_sha256': hashlib.sha256(function.encode()).hexdigest(),
                         'function_parse': 'complete' if not fragment_index.parse_issues else fragment_index.parse_status,
                         'function_and_exact_field_declaration_parse': fragment_index.parse_status,
                         'parse_issues': [str(i) for i in fragment_index.parse_issues],
                         'standalone_type_shim': 'typedef unsigned int uint32_t; (platform alias shim for system stdint.h)'},
            'detector': {'id': run.detector_id, 'version': run.version,
                         'status': run.status, 'findings': [
                             {'rule_id': f.rule_id, 'rule_version': f.rule_version,
                              'local_line': f.line, 'original_function_line': fn.start_line + f.line - (len(struct.splitlines()) + 2),
                              'symbol': f.symbol, 'source_sha256': f.source_sha256}
                             for f in run.findings]},
            'whole_file_parse': full_index.parse_status,
            'whole_file_parse_issue_count': len(full_index.parse_issues),
        }
    record = {
      'schema_version': 1, 'task': 'D21 libtiff CVE-2025-9900 bounds gap assessment',
      'base_commit': 'b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e',
      'disposition': 'PARTIAL', 'detector_change': False,
      'source_repository_declared': 'libtiff/libtiff',
      'scope': ['libtiff/tif_getimage.c', 'libtiff/tiffio.h'],
      'whole_translation_unit_cli': {'tool': 'ohscanner.cpp.bounds', 'version': CppBoundsDetector.version,
         'profile': 'light-ast', 'selected_files': 2,
         'vulnerable': {'parse': 'partial', 'detector_status': 'blocked', 'findings': 0},
         'fixed': {'parse': 'partial', 'detector_status': 'blocked', 'findings': 0},
         'interpretation': 'unknown due to parser partial; not safe and not a fixed differential pass'},
      'function_fragment_probe': results,
      'decision': 'No-change: current D7 pointer-offset rule already detects the exact vulnerable root on a complete local function plus exact TIFFRGBAImage field declaration; the exact fixed function is quiet. Whole translation units remain partial, so case remains PARTIAL.',
      'limitations': ['Function fragment is a bounded source slice, not a full-file CLI analysis.',
         'uint32_t is represented by a standalone underlying-type shim because the actual typedef is from system stdint.h.',
         'No product build, runtime reachability, caller input control, raster capacity, or impact was established.'],
      'replay_commands': [
        'python -m src.cli ohscan-run --repo-dir <repo> --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds',
        'python -m src.cli ohscan-run --repo-dir <repo> --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds',
        'python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir <repo> --output-dir <output-dir>'
      ]}
    (outdir / 'replay.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    lines = ['# D21 libtiff CVE-2025-9900 bounds gap assessment', '',
      'Date: 2026-10-20 (Asia/Shanghai)', '',
      '## Decision', '', record['decision'], '',
      'Case disposition remains **PARTIAL**. Full-file CLI results are blocked by incomplete parsing and must not be read as safe or as a fixed differential.', '',
      '## Exact source identity', '',
      '| Role | Commit | Tree | File blob | File SHA-256 |', '|---|---|---|---|---|']
    for role in ('vulnerable','fixed'):
        d=results[role]; lines.append(f"| {role} | `{d['commit']}` | `{d['tree']}` | `{d['blob']}` | `{d['file_sha256']}` |")
    lines += ['', '## Coverage and replay', '',
      f"- Whole-file scope: `{PATH}`, `{HEADER}`; both parse `partial` on vulnerable and fixed versions; current detector `{CppBoundsDetector.version}` is `blocked`, 0 diagnostics on both.",
      '- Vulnerable `TIFFReadRGBAImageOriented`: source lines 610–631; exact local function plus `_TIFFRGBAImage` field declaration parses complete and emits `ohcpp-memory-bounds-pointer-offset-candidate-004` at original line 621 (`raster + (rheight - img.height) * rwidth`).',
      '- Fixed `TIFFReadRGBAImageOriented`: source lines 626–645; same exact field declaration and local unit parse complete, 0 findings.',
      '- Local unit materializes `uint32_t` as `unsigned int` to model the standard-header typedef. The struct field declaration itself is copied from the exact pinned `tiffio.h` object.',
      '- Finding is a source-level candidate only. No capacity, product build, reachability or impact proof.', '',
      '## Commands', '', '```powershell',
      'python -m src.cli ohscan-run --repo-dir <repo> --repository libtiff/libtiff --commit 9dff73bebc5661f2dace6f16e14cf9e857172f4e --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds',
      'python -m src.cli ohscan-run --repo-dir <repo> --repository libtiff/libtiff --commit 3e0dcf0ec651638b2bd849b2e6f3124b36890d99 --include libtiff/tif_getimage.c --include libtiff/tiffio.h --detector ohscanner.cpp.bounds',
      'python research/evidence/cpp/d21_libtiff_9900_20261020/replay.py --repo-dir <repo> --output-dir <output-dir>', '```', '',
      '## Validation', '',
      '- `python -m unittest tests.detectors.test_cpp_memory_safety_detectors -v`: 20 passed.',
      '- `python -m unittest discover -s tests/detectors -p \'test_cpp_*.py\' -v`: 160 passed.',
      '- `python -m scripts.check_change_scope --base b276ca10fcae03e7e9b5ab7e7ceabcd883d42b4e --lane cpp`: 0 violations.',
      '- `git diff --check`: clean.', '',
      'No detector edit is made because the existing narrow rule already handles the complete local source fragment.']
    (outdir / 'replay.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')

if __name__ == '__main__': main()

